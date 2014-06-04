package uenc.app;

import java.io.File;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;
import java.util.concurrent.TimeUnit;

import uenc.UpdatableEncryption;
import cpabe.Cpabe;

public class UencDecParallel {
	
	private static String currentPath = System.getProperty("user.dir") + File.separator;
	private static String encUencPath = currentPath + "enc_by_uenc" + File.separator;
	private static String decCpabePath = currentPath + "dec_by_cpabe" + File.separator;
	private static String decUencPath = currentPath + "dec_by_uenc" + File.separator;
	
	private static String uskPath = currentPath + "usk" + File.separator;
	private static String singleKeysPath = currentPath	+ "single_keys" + File.separator;
	
	private static String publicKey = singleKeysPath + "pub_key";
	private static String privateKey = singleKeysPath + "prv_key";
	
	public static void main(String[] args) throws Exception {
		
		checkPath(decCpabePath);
		checkPath(decUencPath);
		if(!isPathExists(uskPath) || !isPathExists(singleKeysPath) || !isPathExists(encUencPath))
		{
			System.out.println("Error: The input directories are not existed.");
			System.exit(0);
		}
		
		int numofSamples = 100;
		
		if (args.length > 0) {
			if (args[0].equals("-h")) {
				System.out.println("Usage:");
				System.out.println("uenc_dec_parallel [numofSamples]");
				System.exit(0);
			}

			numofSamples = Integer.parseInt(args[0]);
		}
		
		ForkJoinPool fjp = new ForkJoinPool();
		fjp.submit(new UencDecTask(0, numofSamples - 1));
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
	
	private static class UencDecTask extends RecursiveAction {
		private int start;
		private int end;
		private String filePrefix = "cpabe_";
		private String filePostfix = ".txt";

		public UencDecTask(int start, int end) {
			this.start = start;
			this.end = end;
		}

		@Override
		protected void compute() {
			if ((end - start) <= 5) {
				for (int i = start; i <= end; i++) {

					System.out.println(i);
					String uskFile = uskPath + this.filePrefix + i + this.filePostfix + ".usk";
					
					String encFileByAbeUenc = encUencPath + this.filePrefix + i + this.filePostfix + ".cpabe.uenc";
					String decFileByUenc = decUencPath + this.filePrefix + i + this.filePostfix + ".cpabe";
					String decFile = decCpabePath + this.filePrefix + i + this.filePostfix;

					Cpabe cpabe = new Cpabe();
					UpdatableEncryption uenc = new UpdatableEncryption();
					
					try {
						uenc.uDecrypt(encFileByAbeUenc, decFileByUenc, uskFile);
						cpabe.dec(publicKey, privateKey, decFileByUenc, decFile);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			} else {
				int middle = (start + end) / 2;
				UencDecTask left = new UencDecTask(start, middle);
				UencDecTask right = new UencDecTask(middle + 1, end);
				left.fork();
				right.fork();
			}
		}
	}

}
