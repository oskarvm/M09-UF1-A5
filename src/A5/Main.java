package A5;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Iterator;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        Xifrar xifrar = new Xifrar();

        //1.1.i Genera un parell de claus (KeyPair) de 1024bits, i utilitza-les per xifrar i desxifrar un missatge.
        String text;
        KeyPair pair = xifrar.randomGenerate(1024);

        //1.1.ii Fes que el missatge a xifrar s’entri pel teclat.
        System.out.println("Digues-me el text a xifrar: ");
        text = scanner.nextLine();
        byte[] data = text.getBytes();
        byte[] xifrat = xifrar.encryptData(data, pair.getPublic());
        byte[] desxifrat = xifrar.decryptData(xifrat, pair.getPrivate());

        //1.1.iiii Fes servir els mètodes getPublic i getPrivate per obtenir les claus i el mètodes derivats d’aquestes claus i observa quines dades aporten.
        System.out.println("Clua privada:");
        System.out.println(pair.getPrivate());
        System.out.println("");
        System.out.println("Clau publica:");
        System.out.println(pair.getPublic());
        System.out.println("");
        System.out.println("Text xifrat:");
        System.out.println(xifrat);
        System.out.println("");
        System.out.println("Text desxifrat:");
        System.out.println(new String(desxifrat));


        // 1.2.i Fés la lectura d’un dels keystore que tinguis al teu sistema i extreu-ne la següent informació
        KeyStore ks = xifrar.loadKeyStore("keystore_oscar","usuario");

        // 1.2.1 Tipus de keystore que és (JKS, JCEKS, PKCS12, ...)
        System.out.println("Tipus del keystore: " + ks.getType());

        // 1.2.2 Mida del magatzem (quantes claus hi ha?)
        System.out.println("Tamany del keystore: " + ks.size());

        // 1.2.3 Àlies de totes les claus emmagatzemades
        System.out.println("Alias del keystore: " + ks.aliases());

        // 1.2.4 El certificat d’una de les claus
        System.out.println("Certifict d'una clau del keystore: " + ks.getCertificate("clauOscar"));

        // 1.2.5 L'algorisme de xifrat d’alguna de les claus
        System.out.println("Algoritme d'una clau del keystore: " + ks.getKey("clauOscar", "usuario".toCharArray()).getAlgorithm());

        // 1.2.ii Crea una nova clau simètrica (SecretKey) i desa-la (setEntry) al keystore.
        //Tingueu en compte que si deseu (mètode store) amb una altra contrasenya el keystore queda modificat.
        String passwd = "usuario";
        SecretKey secretKey = Xifrar.keygenKeyGeneration(256);
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(passwd.toCharArray());
        ks.setEntry("secretKeyAlias", skEntry, protectionParameter);

        try (
                FileOutputStream fileOutputStream = new FileOutputStream("keystore_oscar")){
            ks.store(fileOutputStream, "usuario".toCharArray());
        }

        System.out.println(ks.getEntry("secretKeyAlias", protectionParameter));

        //1.3 Fes un funció que donat un fitxer amb un certificat (.cer) retorni la seva PublicKey. Usa aquesta funció i mostra per pantalla les dades de la PublicKey llegida.
        FileInputStream fileInputStream = new FileInputStream("oscar.cer");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection c = certificateFactory.generateCertificates(fileInputStream);
        Iterator i = c.iterator();
        while (i.hasNext()) {
            Certificate cert = (Certificate)i.next();
            System.out.println(cert);
        }

        //1.4 Llegir una clau asimètrica del keystore i extreure’n la PublicKey. Imprimir-la per pantalla.
        //Podeu crear una funció igual que en el punt 3 fent sobrecàrrega)

        FileInputStream is = new FileInputStream("keystore_oscar");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "usuario".toCharArray());

        String alias = "clauOscar";

        Key key = keystore.getKey(alias, "usuario".toCharArray());
        if (key instanceof PrivateKey) {

            Certificate cert = keystore.getCertificate(alias);

            PublicKey publicKey = cert.getPublicKey();
            System.out.println(publicKey.toString());
        }

        //1.5 Fer un funció que donades unes dades i una PrivateKey retorni la signatura. Usa-la i mostra la signatura per pantalla. (funció dels apunts 1.3.1)
        byte[] dataBy = "dadesPerOscar".getBytes();
        PrivateKey privKey = pair.getPrivate();
        byte[] firma = Xifrar.signData(dataBy,privKey);
        System.out.println(new String(firma));

        //1.6 Fer una funció que donades unes dades, una signatura i la PublicKey, comprovi la validesa de la informació. (funció dels apunts 1.3.2)
        PublicKey publicKey = pair.getPublic();
        boolean verificado = Xifrar.validateSignature(dataBy,firma,publicKey);
        System.out.println(verificado);

        //2.2 Genereu un parell de claus (KeyPair) i proveu de xifrar i desxifrar un text amb clau embolcallada.
        KeyPair claus = Xifrar.randomGenerate(1024);
        PublicKey pubKey = claus.getPublic();
        PrivateKey privateKey = claus.getPrivate();
        byte[][] wrappedKeyEncrypt = Xifrar.encryptWrappedData(dataBy,pubKey);
        byte[]  wrappedKeyDecrypt = Xifrar.decryptWrappedData(wrappedKeyEncrypt,privateKey);
        System.out.println(new String(wrappedKeyDecrypt));
    }

}

