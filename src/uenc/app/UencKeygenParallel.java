package uenc.app;

import java.io.File;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;
import java.util.concurrent.TimeUnit;

import uenc.AccessTreeBuilder;
import uenc.UpdatableEncryption;
import cpabe.Cpabe;

public class UencKeygenParallel {

	public static void main(String[] args) throws Exception {

		int numofAttributes = 15;
		int numofUsks = 100;
		String uskPath = System.getProperty("user.dir") + File.separator
				+ "usk" + File.separator;
		String singleKeysPath = System.getProperty("user.dir") + File.separator
				+ "single_keys" + File.separator;
		
		checkPath(uskPath);
		checkPath(singleKeysPath);

		if (args.length > 0) {
			if (args[0].equals("-h")) {
				System.out.println("Usage:");
				System.out
						.println("uenc_keygen_parallel [numofAttributes] [numofUsks]");
				System.exit(0);
			}

			numofAttributes = Integer.parseInt(args[0]);
			numofUsks = Integer.parseInt(args[1]);
		}

		String publicKey = singleKeysPath + "pub_key";
		String masterKey = singleKeysPath + "master_key";
		String privateKey = singleKeysPath + "prv_key";

		String ugpFile = singleKeysPath + "ugp";
		String xFile = singleKeysPath + "x";

		String attrString = AccessTreeBuilder
				.getAttributesString(numofAttributes);

		Cpabe cpabe = new Cpabe();
		UpdatableEncryption uenc = new UpdatableEncryption();

		cpabe.setup(publicKey, masterKey);
		uenc.uSetup(ugpFile, xFile);
		cpabe.keygen(publicKey, privateKey, masterKey, attrString);

		ForkJoinPool fjp = new ForkJoinPool();
		fjp.submit(new UencKeygenTask(0, numofUsks - 1, uskPath, ugpFile, xFile));
		fjp.shutdown();
		try {
			fjp.awaitTermination(7200, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

	}

	private static class UencKeygenTask extends RecursiveAction {
		private int start;
		private int end;
		private String filePrefix = "cpabe_";
		private String filePostfix = ".txt";
		private String resultPath;
		private String ugpFile;
		private String xFile;

		public UencKeygenTask(int start, int end, String resultPath,
				String ugpFile, String xFile) {
			this.start = start;
			this.end = end;
			this.resultPath = resultPath;
			this.ugpFile = ugpFile;
			this.xFile = xFile;
		}

		@Override
		protected void compute() {
			if ((end - start) <= 5) {
				for (int i = start; i <= end; i++) {

					System.out.println(i);
					String uskFile = resultPath + this.filePrefix + i
							+ this.filePostfix + ".usk";

					UpdatableEncryption uenc = new UpdatableEncryption();
					try {
						uenc.uKeygen(ugpFile, xFile, uskFile);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			} else {
				int middle = (start + end) / 2;
				UencKeygenTask left = new UencKeygenTask(start, middle,
						resultPath, ugpFile, xFile);
				UencKeygenTask right = new UencKeygenTask(middle + 1, end,
						resultPath, ugpFile, xFile);
				left.fork();
				right.fork();
			}
		}
	}
	
	public static void checkPath(String path)
	{
		File f = new File(path);
		
		if(!f.isDirectory())
		{
			f.mkdir();
		}
			
	}

}
