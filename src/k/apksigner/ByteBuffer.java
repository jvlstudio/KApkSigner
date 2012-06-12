package k.apksigner;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class ByteBuffer extends OutputStream {
	public static byte[] getBytes(File file) {
		ByteBuffer buffer = new ByteBuffer();
		buffer.write(file);
		return buffer.getBytes();
	}

	public static byte[] getBytes(InputStream is) {
		ByteBuffer buffer = new ByteBuffer();
		buffer.write(is);
		return buffer.getBytes();
	}

	private final ByteArrayOutputStream baos = new ByteArrayOutputStream();

	public byte[] getBytes() {
		return baos.toByteArray();
	}

	@Override
	public synchronized void write(byte[] b) {
		write(b, 0, b.length);
	}

	public synchronized void write(byte[] b, int len) {
		write(b, 0, len);
	}

	@Override
	public synchronized void write(byte[] b, int off, int len) {
		baos.write(b, off, len);
	}

	public synchronized void write(File file) {
		try {
			write(new FileInputStream(file));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public synchronized void write(InputStream is) {
		try {
			byte[] buffer = new byte[8192];
			int read;
			while ((read = is.read(buffer)) > 0) {
				write(buffer, read);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public synchronized void write(int oneByte) {
		baos.write(oneByte);
	}
}
