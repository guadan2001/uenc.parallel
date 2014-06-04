package uenc.app;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;
import java.util.concurrent.TimeUnit;

import uenc.AccessTreeBuilder;
import uenc.UpdatableEncryption;
import cpabe.Cpabe;

public class UencEncParallel {
	
	private static String currentPath = System.getProperty("user.dir") + File.separator;
	private static String encCpabePath = currentPath + "enc_by_cpabe" + File.separator;
	private static String encUencPath = currentPath + "enc_by_uenc" + File.separator;
	
	private static String uskPath = currentPath + "usk" + File.separator;
	private static String inputFilePath = currentPath + "input" + File.separator;
	private static String singleKeysPath = currentPath	+ "single_keys" + File.separator;
	
	private static String publicKey = singleKeysPath + "pub_key";
	private static String ugpFile = singleKeysPath + "ugp";
	
	private static String attrString;
	private static String policy;
	
	public static void main(String[] args) throws Exception {
		
		checkPath(encCpabePath);
		checkPath(encUencPath);
		if(!isPathExists(uskPath) || !isPathExists(singleKeysPath))
		{
			System.out.println("Error: The keys' directories are not existed.");
			System.exit(0);
		}
		
		int numofAttributes = 20;
		int numofSamples = 100;
		int policyType = 1;
		
		if (args.length > 0) {
			if (args[0].equals("-h")) {
				System.out.println("Usage:");
				System.out.println("uenc_enc_parallel [numofAttributes] [numofSamples] [policyType]");
				System.exit(0);
			}

			numofAttributes = Integer.parseInt(args[0]);
			numofSamples = Integer.parseInt(args[1]);
			policyType = Integer.parseInt(args[2]);
		}
		
		attrString = AccessTreeBuilder.getAttributesString(numofAttributes);
		policy = AccessTreeBuilder.getPolicyString(numofAttributes, attrString, policyType);

		ForkJoinPool fjp = new ForkJoinPool();
		fjp.submit(new UencEncTask(0, numofSamples - 1));
		fjp.shutdown();
		try {
			fjp.awaitTermination(7200, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	private static boolean isPathExists(String path)
	{
		File f = new File(path);
		if(f.isDirectory())
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	
	private static void checkPath(String path)
	{
		File f = new File(path);
		if(!f.isDirectory())
		{
			f.mkdir();
		}
	}
	
	private static class UencEncTask extends RecursiveAction {
		private int start;
		private int end;
		private String filePrefix = "cpabe_";
		private String filePostfix = ".txt";

		public UencEncTask(int start, int end) {
			this.start = start;
			this.end = end;
		}

		@Override
		protected void compute() {
			if ((end - start) <= 5) {
				for (int i = start; i <= end; i++) {

					System.out.println(i);
					String uskFile = uskPath + this.filePrefix + i + this.filePostfix + ".usk";
					
					String inputFile = inputFilePath + this.filePrefix + i + this.filePostfix;
					String encFileByAbe = encCpabePath + this.filePrefix + i + this.filePostfix + ".cpabe";
					String encFileByAbeUenc = encUencPath + this.filePrefix + i + this.filePostfix + ".cpabe.uenc";

					Cpabe cpabe = new Cpabe();
					UpdatableEncryption uenc = new UpdatableEncryption();
					
					try {
						cpabe.enc(publicKey, policy, inputFile, encFileByAbe);
						uenc.uEncrypt(ugpFile, uskFile, encFileByAbe, encFileByAbeUenc);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			} else {
				int middle = (start + end) / 2;
				UencEncTask left = new UencEncTask(start, middle);
				UencEncTask right = new UencEncTask(middle + 1, end);
				left.fork();
				right.fork();
			}
		}
	}

}
