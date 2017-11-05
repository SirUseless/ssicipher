import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarExamen {
	
	/**
	 * 
	 * @param args[0] paquete
	 * @param args[1] examen crudo 
	 * @param args[2] clave publica sellado
	 * @param args[3] clave publica alumo
	 * @param args[4] clave privada profesor
	 * 
	 */
	public static void main(String args[]) throws Exception{
		if (args.length != 5) {
			mensajeAyuda();
			System.exit(1);
		}
		
		System.out.println("Cargando recusrsos...");
		
		Security.addProvider(new BouncyCastleProvider());
		
		//1. CARGAMOS PAQUETE DE ALUMNO
		Paquete paquete = PaqueteDAO.leerPaquete(args[0]);
		
		//2. CARGAMOS CLAVES
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
		
		//KR profesor
		File fclavePrivadaProfesor = new File(args[4]);
		byte[] bprivate = new byte[(int) fclavePrivadaProfesor.length()];
		
		InputStream in = new FileInputStream(fclavePrivadaProfesor);
		in.read(bprivate, 0, (int) fclavePrivadaProfesor.length());
		in.close();
		
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bprivate);
		PrivateKey clavePrivadaProfesor = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
		
		//KU autoridad sellado
		File fclavePublicaSellado = new File(args[2]);
		byte[] bpublic = new byte[(int) fclavePublicaSellado.length()];
		
		InputStream in2 = new FileInputStream(fclavePublicaSellado);
		in2.read(bpublic, 0, (int) fclavePublicaSellado.length());
		in2.close();
		
		X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bpublic);
		PublicKey clavePublicaSellado = keyFactoryRSA.generatePublic(clavePublicaSpec);
		
		//KU alumno
		File fclavePublicaAlumno = new File(args[3]);
		bpublic = new byte[(int) fclavePublicaAlumno.length()];
		
		InputStream in3 = new FileInputStream(fclavePublicaAlumno);
		in3.read(bpublic, 0, (int) fclavePublicaAlumno.length());
		in3.close();
		
		clavePublicaSpec = new X509EncodedKeySpec(bpublic);
		PublicKey clavePublicaAlumno = keyFactoryRSA.generatePublic(clavePublicaSpec);
		
		//3. cargar examen
		File examen = new File(args[1]);
		
		try{
			boolean integridad = comprobarIntegridad(paquete, clavePrivadaProfesor, clavePublicaAlumno, examen);
			boolean sellado = comprobarSello(paquete, clavePublicaSellado, clavePublicaAlumno);
			
			if (sellado && integridad) {
				System.out.println("Paquete recibido en perfecto estado. Asegurado no repudio, confidencialidad y timestamp verídico");
			}
		}catch(BadPaddingException e){
			System.out.println("Clave DES corrupta.");
		}
		
		
		System.out.println("Finalizando...");
	}
	
	private static boolean comprobarIntegridad(Paquete paquete, PrivateKey krprofesor, PublicKey kualumno, File examenOriginal) throws Exception{
		System.out.println("Comprobando integridad:");
		Bloque bqExamen = paquete.getBloque("datosCifrado");
		Bloque bqClaveDES = paquete.getBloque("ClaveSecreta");
		Bloque bqFirma = paquete.getBloque("Firma");
		byte[] examenCifrado = bqExamen.getContenido();
		byte[] claveDESRSA = bqClaveDES.getContenido();
		byte[] firmaCifrada = bqFirma.getContenido();
		
		System.out.println("\tObteniento clave DES...");
		//Desciframos clave des con kr profesor
		Cipher cifrador = Cipher.getInstance("RSA","BC");
		cifrador.init(Cipher.DECRYPT_MODE, krprofesor);
		byte[] bclaveDES = cifrador.doFinal(claveDESRSA);
		
		DESKeySpec DESspec = new DESKeySpec(bclaveDES);
		SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES","BC");
		SecretKey claveDES = secretKeyFactoryDES.generateSecret(DESspec);
		
		System.out.println("\tDescifrando examen...");
		//Desciframos examen con clave des
		cifrador = Cipher.getInstance("DES","BC");
		cifrador.init(Cipher.DECRYPT_MODE, claveDES);
		byte[] examenDescifrado = cifrador.doFinal(examenCifrado);
		
		//Comparamos examen recibido con examen enviado
		File fexamenDescifrado = new File("examenDescifrado");
		FileOutputStream fout = new FileOutputStream(fexamenDescifrado);
		fout.write(examenDescifrado);
		fout.close();
		System.out.println("\tEl examen descifrado ha sido guardado como 'examenDescifrado'");
		
		byte[] bexamenOriginal = Files.readAllBytes(examenOriginal.toPath());
		
		System.out.println("\tObteniendo firma de examen descifrado...");
		
		//obtener firma descifrado
		MessageDigest messageDigest = MessageDigest.getInstance("SHA");
		messageDigest.update(examenDescifrado);
		byte[] firmaGenerada = messageDigest.digest();
		
		//descifrar firma recibida
		System.out.println("\tDescifrando firma recibida...");
		cifrador = Cipher.getInstance("RSA","BC");
		cifrador.init(Cipher.DECRYPT_MODE, kualumno);
		byte[] firmaRecibida = cifrador.doFinal(firmaCifrada);

		if(Arrays.equals(firmaGenerada, firmaRecibida)){
			System.out.println("\tLa firma recibida coincide con el resumen generado.");
			if(!Arrays.equals(examenDescifrado, bexamenOriginal)){
				System.out.println("\tEl examen recibido es distinto del enviado.");
				return false;
			}else{
				System.out.println("\tEl examen recibido es igual al enviado.");
				return true;
			}
		}else{
			System.out.println("\tLa firma recibida no coincide con el resumen generado.");
			return false;
		}
		
	}
	
	private static boolean comprobarSello(Paquete paquete, PublicKey kusellador, PublicKey kualumno) throws Exception{
		System.out.println("Comprobando sello:");
		Bloque bqFirma = paquete.getBloque("Firma");
		Bloque bqSello = paquete.getBloque("Sello");
		Bloque bqTimestamp = paquete.getBloque("Timestamp");
		byte[] firmaCifrada = bqFirma.getContenido();
		byte[] selloCifrado = bqSello.getContenido();
		byte[] timestamp = bqTimestamp.getContenido();

		
		System.out.println("\tDescifrando sello...");
		Cipher cifrador = Cipher.getInstance("RSA","BC");
		cifrador.init(Cipher.DECRYPT_MODE, kusellador);
		byte[] selloRecibido = cifrador.doFinal(selloCifrado);

		
		System.out.println("\tGenerando sello de comprobación...");
		MessageDigest messageDigest = MessageDigest.getInstance("SHA");
		messageDigest.update(firmaCifrada);
		messageDigest.update(timestamp);
		byte[] selloGenerado = messageDigest.digest();

		
		if(Arrays.equals(selloRecibido, selloGenerado)){
			System.out.println("\tSellado OK");
			return true;
		}
	
		System.out.println("\tSellado corrupto");
		return false;
	}
		
	
	public static void mensajeAyuda() {
		System.out.println("Sellador de examenes para SSI");
		System.out.println("\tSintaxis:   java DesempaquetarExamen paquete examen KUsellado KUalumno KRprofesor");
		System.out.println();
	}
}
