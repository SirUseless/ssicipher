import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EmpaquetarExamen {
	
	/**
	 * @param arg[0] nombreExamen
	 * @param arg[1] nombrePaquete
	 * @param arg[2] clavePublicaProfesor
	 * @param arg[3] clavePrivadaAlumno
	 * @throws Exception
	 */
	public static void main(String args[])throws Exception{
		if (args.length != 4) {
			mensajeAyuda();
			System.exit(1);
		}
		//1.CIFRADO DES
		//Cargar provider
		Security.addProvider(new BouncyCastleProvider());
		
		//Crear paquete
		Paquete examen = new Paquete();
		
		//Crear e inicializar clave DES aleatoria
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56);
		SecretKey clave = generadorDES.generateKey();
		
		//Crear e inicializar cifrador DES
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
		cifrador.init(Cipher.ENCRYPT_MODE, clave);
		
		//Lemos arquivo de exame
		File file = new File(args[0]);
		FileInputStream in = new FileInputStream(file);
		byte fileContent[] = new byte[(int) file.length()];
		in.read(fileContent);
		in.close();
		
		//cifrar e almacenar o cifrado
		byte[] bytecifrado = cifrador.doFinal(fileContent);
		
		examen.anadirBloque("datosCifrado", new Bloque("datosCifrado",bytecifrado));
		
		//2.CIFRAR CLAVE DES CON RSA
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
		
		//Obtemos KU de profesor
		File cpublicaprofesor = new File(args[2]);
		FileInputStream input;
		input = new FileInputStream(cpublicaprofesor);
		byte[] bpublic = new byte[(int)cpublicaprofesor.length()];
		input.read(bpublic, 0, (int)cpublicaprofesor.length());
		input.close();
		
		//Obtemos KR de alumno
		File cprivadaalumno = new File(args[3]);
		byte[] bprivate = new byte[(int) cprivadaalumno.length()];
		input = new FileInputStream(cprivadaalumno);
		input.read(bprivate, 0, (int) cprivadaalumno.length());
		input.close();
		
		X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bpublic);
		PublicKey clavePublicaProfesor = keyFactoryRSA.generatePublic(clavePublicaSpec);
		
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bprivate);
		PrivateKey clavePrivadaAlumno = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
		
		//Ciframos clave DES con clave de Profesor
		cifrador=Cipher.getInstance("RSA","BC");
		cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaProfesor );
		bytecifrado= cifrador.doFinal(clave.getEncoded());
		
		//engadimos a clave cifrada
		examen.anadirBloque("ClaveSecreta", new Bloque("ClaveSecreta",bytecifrado));
		
		//3.CIFRAR HASH SHA CON RSA
		
		MessageDigest messageDigest = MessageDigest.getInstance("SHA");

		/* Leer fichero de 1k en 1k y pasar fragmentos leidos a la funcion resumen */
		byte[] buffer = new byte[1000];
		FileInputStream in2 = new FileInputStream(args[0]);
		int leidos = in2.read(buffer, 0, 1000);
		while (leidos != -1) {
			messageDigest.update(buffer, 0, leidos);
			leidos = in2.read(buffer, 0, 1000);
		}
		in2.close();
			
		byte[] resumen = messageDigest.digest();
		
		cifrador.init(Cipher.ENCRYPT_MODE, clavePrivadaAlumno);
		bytecifrado = cifrador.doFinal(resumen);
		
		examen.anadirBloque("Firma", new Bloque("Firma",bytecifrado));
		
		PaqueteDAO.escribirPaquete(args[1], examen);
		System.out.println("Paquete creado correctamente");
	}
	
	public static void mensajeAyuda() {
		System.out.println("Empaquetador de examenes para SSI");
		System.out.println("\tSintaxis:   java EmpaquetarExamen examen nombrePaquete clavePublicaProfesor clavePrivadaAlumno");
		System.out.println();
	}
}
