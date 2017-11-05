import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SellarExamen {
	
	/**
	 * 
	 * @param args[0] paquete
	 * @param args[1] clavePrivadaESellado
	 */
	public static void main(String args[]) throws Exception{
		if (args.length != 2) {
			mensajeAyuda();
			System.exit(1);
		}
		Security.addProvider(new BouncyCastleProvider());
		
		//1. CARGAMOS PAQUETE DE ALUMNO
		Paquete paquete = PaqueteDAO.leerPaquete(args[0]);
		
		//2. CARGAMOS CLAVE PRIVADA DE ENTIDAD SELLADO
		File clavePrivadaESellado = new File(args[1]);
		byte[] bprivate = new byte[(int) clavePrivadaESellado.length()];
		
		InputStream in = new FileInputStream(clavePrivadaESellado);
		in.read(bprivate, 0, (int) clavePrivadaESellado.length());
		in.close();
		
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bprivate);
		PrivateKey clavePrivadaAutoridadCertificadora = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
		
		//3. GENERAMOS TIMESTAMP Y AÑADIMOS A PAQUETE
		java.sql.Timestamp timestamp = new java.sql.Timestamp(System.currentTimeMillis());
		paquete.anadirBloque("timestamp", new Bloque("timestamp", timestamp.toString().getBytes()));
				
		//4. CREAMOS HASH DE FIRMA+TIMESTAMP
		MessageDigest messageDigest = MessageDigest.getInstance("SHA");
		
		Bloque firmab =paquete.getBloque("Firma");
		byte [] firma = firmab.getContenido();
		
		messageDigest.update(firma);
		messageDigest.update(timestamp.toString().getBytes());
		
		byte[] resumen = messageDigest.digest();
		
		//5. ENCRIPTAMOS ASIMETRICAMENTE Y ACTUALIZAMOS PAQUETE
		
		Cipher cifrador=Cipher.getInstance("RSA","BC");
		cifrador.init(Cipher.ENCRYPT_MODE, clavePrivadaAutoridadCertificadora );
		byte[] sello = cifrador.doFinal(resumen);
		
		paquete.anadirBloque("Sello", new Bloque("Sello",sello));
		
		PaqueteDAO.escribirPaquete(args[0], paquete);
		System.out.println("Paquete sellado correctamente");
	}
	
	public static void mensajeAyuda() {
		System.out.println("Sellador de examenes para SSI");
		System.out.println("\tSintaxis:   java SellarExamen paqueteExamen clavePrivadaEntidadSellado");
		System.out.println();
	}
}
