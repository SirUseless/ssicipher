import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

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
		in2.read(bprivate, 0, (int) fclavePublicaSellado.length());
		in2.close();
		
		X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bpublic);
		PublicKey clavePublicaSellado = keyFactoryRSA.generatePublic(clavePublicaSpec);
		
		//KU alumno
		File fclavePublicaAlumno = new File(args[3]);
		bpublic = new byte[(int) fclavePublicaAlumno.length()];
		
		InputStream in3 = new FileInputStream(fclavePublicaAlumno);
		in3.read(bprivate, 0, (int) fclavePublicaAlumno.length());
		in3.close();
		
		clavePublicaSpec = new X509EncodedKeySpec(bpublic);
		PublicKey clavePublicaAlumno = keyFactoryRSA.generatePublic(clavePublicaSpec);
		
		//3. cargar examen
		File examen = new File(args[1]);
	}
	
	private boolean comprobarIntegridad(Paquete paquete, ){
		
		return false;
	}
	
	private boolean comprobarAutoridadSellado(){
		
		return false;
	}
	
	private boolean comprobarNoRepudio(){
		
		return false;
	}
	
	
	public static void mensajeAyuda() {
		System.out.println("Sellador de examenes para SSI");
		System.out.println("\tSintaxis:   java DesempaquetarExamen paquete examen KUsellado KUalumno KRprofesor");
		System.out.println();
	}
}
