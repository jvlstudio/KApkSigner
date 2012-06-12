package k.apksigner;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import sun.misc.BASE64Encoder;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

public class Signer {
	private static class SignatureOutputStream extends FilterOutputStream {
		private int mCount;
		private Signature mSignature;

		public SignatureOutputStream(OutputStream out, Signature sig) {
			super(out);
			mSignature = sig;
			mCount = 0;
		}

		public int size() {
			return mCount;
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			try {
				mSignature.update(b, off, len);
			} catch (SignatureException e) {
				throw new IOException("SignatureException: " + e);
			}
			super.write(b, off, len);
			mCount += len;
		}

		@Override
		public void write(int b) throws IOException {
			try {
				mSignature.update((byte) b);
			} catch (SignatureException e) {
				throw new IOException("SignatureException: " + e);
			}
			super.write(b);
			mCount++;
		}
	}

	private static final String CERT_RSA_NAME = "META-INF/CERT.RSA";

	private static final String CERT_SF_NAME = "META-INF/CERT.SF";

	private static Pattern stripPattern = Pattern
			.compile("^META-INF/(.*)[.](SF|RSA|DSA)$");

	private static Manifest addDigestsToManifest(JarFile jar)
			throws IOException, GeneralSecurityException {
		Manifest input = jar.getManifest();
		Manifest output = new Manifest();
		Attributes main = output.getMainAttributes();
		if (input != null) {
			main.putAll(input.getMainAttributes());
		} else {
			main.putValue("Manifest-Version", "1.0");
			main.putValue("Created-By", "1.0 (KApkSigner)");
		}

		BASE64Encoder base64 = new BASE64Encoder();
		MessageDigest md = MessageDigest.getInstance("SHA1");
		byte[] buffer = new byte[4096];
		int num;

		TreeMap<String, JarEntry> byName = new TreeMap<String, JarEntry>();

		for (Enumeration<JarEntry> e = jar.entries(); e.hasMoreElements();) {
			JarEntry entry = e.nextElement();
			byName.put(entry.getName(), entry);
		}

		for (JarEntry entry : byName.values()) {
			String name = entry.getName();
			if (!entry.isDirectory()
					&& !name.equals(JarFile.MANIFEST_NAME)
					&& !name.equals(Signer.CERT_SF_NAME)
					&& !name.equals(Signer.CERT_RSA_NAME)
					&& (Signer.stripPattern == null || !Signer.stripPattern
							.matcher(name).matches())) {
				InputStream data = jar.getInputStream(entry);
				while ((num = data.read(buffer)) > 0) {
					md.update(buffer, 0, num);
				}

				Attributes attr = null;
				if (input != null) {
					attr = input.getAttributes(name);
				}
				attr = attr != null ? new Attributes(attr) : new Attributes();
				attr.putValue("SHA1-Digest", base64.encode(md.digest()));
				output.getEntries().put(name, attr);
			}
		}

		return output;
	}

	public static void main(String[] args) throws IOException {
		if (args.length < 1 || args.length > 2) {
			System.out
					.println("Usage: java -jar signer.jar unsigned.apk [signed.apk]");
			return;
		}
		boolean replace = args.length < 2;
		File input = new File(args[0]), output = new File(replace ? args[0]
				+ ".singed.apk" : args[1]);
		if (!input.exists() || !input.isFile()) {
			System.out.println("Error: " + input.getName()
					+ " is not exists! Full path: " + input.getAbsolutePath());
			return;
		}
		if (output.exists()) {
			System.out.print("File " + output.getName()
					+ " already exists! Overwrite? [N/y]: ");
			int b = System.in.read();
			if (b == 'Y' || b == 'y') {
				output.delete();
			} else {
				return;
			}
		}
		sign(input, output);
		if (replace) {
			input.delete();
			output.renameTo(input);
		}
	}

	private static void copyFiles(Manifest manifest, JarFile in,
			JarOutputStream out, long timestamp) throws IOException {
		byte[] buffer = new byte[4096];
		int num;
		Map<String, Attributes> entries = manifest.getEntries();
		List<String> names = new ArrayList<String>(entries.keySet());
		Collections.sort(names);
		for (String name : names) {
			JarEntry inEntry = in.getJarEntry(name);
			JarEntry outEntry = null;
			if (inEntry.getMethod() == ZipEntry.STORED) {
				outEntry = new JarEntry(inEntry);
			} else {
				outEntry = new JarEntry(name);
			}
			outEntry.setTime(timestamp);
			out.putNextEntry(outEntry);

			InputStream data = in.getInputStream(inEntry);
			while ((num = data.read(buffer)) > 0) {
				out.write(buffer, 0, num);
			}
			out.flush();
		}
	}

	private static KeySpec decryptPrivateKey(byte[] encryptedPrivateKey)
			throws GeneralSecurityException {
		EncryptedPrivateKeyInfo epkInfo;
		try {
			epkInfo = new EncryptedPrivateKeyInfo(encryptedPrivateKey);
		} catch (IOException ex) {
			return null;
		}
		SecretKeyFactory skFactory = SecretKeyFactory.getInstance(epkInfo
				.getAlgName());
		Key key = skFactory.generateSecret(new PBEKeySpec("".toCharArray()));
		Cipher cipher = Cipher.getInstance(epkInfo.getAlgName());
		cipher.init(Cipher.DECRYPT_MODE, key, epkInfo.getAlgParameters());
		return epkInfo.getKeySpec(cipher);
	}

	private static PrivateKey readPrivateKey(InputStream input)
			throws IOException, GeneralSecurityException {
		try {
			byte[] bytes = ByteBuffer.getBytes(input);
			KeySpec spec = Signer.decryptPrivateKey(bytes);
			if (spec == null) {
				spec = new PKCS8EncodedKeySpec(bytes);
			}
			try {
				return KeyFactory.getInstance("RSA").generatePrivate(spec);
			} catch (InvalidKeySpecException ex) {
				return KeyFactory.getInstance("DSA").generatePrivate(spec);
			}
		} finally {
			input.close();
		}
	}

	private static X509Certificate readPublicKey(InputStream input)
			throws IOException, GeneralSecurityException {
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) cf.generateCertificate(input);
		} finally {
			input.close();
		}
	}

	public static void sign(String input, String output) {
		sign(new File(input), new File(output));
	}

	public static void sign(File input, File output) {
		JarFile inputJar = null;
		JarOutputStream outputJar = null;
		FileOutputStream outputFile = null;
		try {
			X509Certificate publicKey = Signer.readPublicKey(Signer.class
					.getResourceAsStream("/key.x509.pem"));
			PrivateKey privateKey = Signer.readPrivateKey(Signer.class
					.getResourceAsStream("/key.pk8"));
			long timestamp = publicKey.getNotBefore().getTime() + 3600L * 1000;
			inputJar = new JarFile(input, false);
			outputFile = new FileOutputStream(output);
			outputJar = new JarOutputStream(outputFile);
			outputJar.setLevel(9);
			Manifest manifest = Signer.addDigestsToManifest(inputJar);
			JarEntry je = new JarEntry(JarFile.MANIFEST_NAME);
			je.setTime(timestamp);
			outputJar.putNextEntry(je);
			manifest.write(outputJar);
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateKey);
			je = new JarEntry(Signer.CERT_SF_NAME);
			je.setTime(timestamp);
			outputJar.putNextEntry(je);
			Signer.writeSignatureFile(manifest, new SignatureOutputStream(
					outputJar, signature));
			je = new JarEntry(Signer.CERT_RSA_NAME);
			je.setTime(timestamp);
			outputJar.putNextEntry(je);
			Signer.writeSignatureBlock(signature, publicKey, outputJar);
			Signer.copyFiles(manifest, inputJar, outputJar, timestamp);
			outputJar.close();
			outputJar = null;
			outputFile.flush();
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		} finally {
			try {
				if (inputJar != null) {
					inputJar.close();
				}
				if (outputFile != null) {
					outputFile.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
				System.exit(1);
			}
		}
	}

	private static void writeSignatureBlock(Signature signature,
			X509Certificate publicKey, OutputStream out) throws IOException,
			GeneralSecurityException {
		SignerInfo signerInfo = new SignerInfo(new X500Name(publicKey
				.getIssuerX500Principal().getName()),
				publicKey.getSerialNumber(), AlgorithmId.get("SHA1"),
				AlgorithmId.get("RSA"), signature.sign());
		PKCS7 pkcs7 = new PKCS7(new AlgorithmId[] { AlgorithmId.get("SHA1") },
				new ContentInfo(ContentInfo.DATA_OID, null),
				new X509Certificate[] { publicKey },
				new SignerInfo[] { signerInfo });
		pkcs7.encodeSignedData(out);
	}

	private static void writeSignatureFile(Manifest manifest,
			SignatureOutputStream out) throws IOException,
			GeneralSecurityException {
		Manifest sf = new Manifest();
		Attributes main = sf.getMainAttributes();
		main.putValue("Signature-Version", "1.0");
		main.putValue("Created-By", "1.0 (KApkSigner)");
		BASE64Encoder base64 = new BASE64Encoder();
		MessageDigest md = MessageDigest.getInstance("SHA1");
		PrintStream print = new PrintStream(new DigestOutputStream(
				new ByteArrayOutputStream(), md), true, "UTF-8");
		manifest.write(print);
		print.flush();
		main.putValue("SHA1-Digest-Manifest", base64.encode(md.digest()));
		Map<String, Attributes> entries = manifest.getEntries();
		for (Map.Entry<String, Attributes> entry : entries.entrySet()) {
			// Digest of the manifest stanza for this entry.
			print.print("Name: " + entry.getKey() + "\r\n");
			for (Map.Entry<Object, Object> att : entry.getValue().entrySet()) {
				print.print(att.getKey() + ": " + att.getValue() + "\r\n");
			}
			print.print("\r\n");
			print.flush();

			Attributes sfAttr = new Attributes();
			sfAttr.putValue("SHA1-Digest", base64.encode(md.digest()));
			sf.getEntries().put(entry.getKey(), sfAttr);
		}
		sf.write(out);
		if (out.size() % 1024 == 0) {
			out.write('\r');
			out.write('\n');
		}
	}
}