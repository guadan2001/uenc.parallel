package uenc.app;

import java.io.File;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;
import java.util.concurrent.TimeUnit;

import uenc.UpdatableEncryption;

public class UencUpdateParallel {
	public static void main(String[] args) throws Exception {
		
		String resultPath = System.getProperty("user.dir") + File.separator
				+ "result" + File.separator;
		
		int numofSamples = 0;

		if (args.length > 0) {
			if (args[0].equals("-h")) {
				System.out.println("Usage:");
				System.out.println("uenc_update_parallel [numofSamples]");
				System.exit(0);
			}

			if(args.length > 0)
			{
				numofSamples = Integer.parseInt(args[0]);
			}
		}
		
		ForkJoinPool fjp = new ForkJoinPool();
		fjp.submit(new UencUpdateTask(0, numofSamples-1, resultPath));
		fjp.shutdown();
		try {
			fjp.awaitTermination(7200, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	private static class UencUpdateTask extends RecursiveAction {
		private int start;
		private int end;
		private String filePrefix = "cpabe_";
		private String filePostfix = ".txt";
		String resultPath;

		public UencUpdateTask(int start, int end, String resultPath) {
			this.start = start;
			this.end = end;
			this.resultPath = resultPath;
		}

		@Override
		protected void compute() {
			if ((end - start) <= 5) {
				for (int i = start; i <= end; i++) {
					
					System.out.println(i);
					String inputFileName = this.filePrefix + i + this.filePostfix;
					String uskFile = resultPath + inputFileName + ".usk";
					String newUskFile = resultPath + inputFileName + ".newusk";
					String rkFile = resultPath + inputFileName + ".rk";

					String encFileByAbeUenc = resultPath + inputFileName + ".cpabe.uenc";
					String encFileByAbeUencUpdated = resultPath
							+ inputFileName + ".cpabe.uenc.updated";
					
					
					UpdatableEncryption uenc = new UpdatableEncryption();
					try {
						uenc.uKeyUpdate(uskFile, newUskFile, rkFile);
						uenc.uEncUpdate(rkFile, encFileByAbeUenc, encFileByAbeUencUpdated);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			} else {
				int middle = (start + end) / 2;
				UencUpdateTask left = new UencUpdateTask(start, middle, resultPath);
				UencUpdateTask right = new UencUpdateTask(middle + 1, end, resultPath);
				left.fork();
				right.fork();
			}
		}
	}

}
