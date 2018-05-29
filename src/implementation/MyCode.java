package implementation;
import code.GuiException;
import gui.Constants;
import java.awt.Component;
import java.awt.Frame;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.util.Enumeration;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.Extensions.*;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import static org.bouncycastle.asn1.x509.X509Extensions.IssuerAlternativeName;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import sun.security.jca.JCAUtil;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.EDIPartyName;
import sun.security.x509.IssuerAlternativeNameExtension;
import x509.v3.GuiV3;

public class MyCode extends x509.v3.CodeV3 {

    private KeyStore keyStore;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Exception ex) {
        }
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        Security.addProvider(new BouncyCastleProvider());
        try {
            if (this.keyStore != null)
                return this.keyStore.aliases();
            else 
                return null;
        } catch (Exception ex) {
            return null;
        } 
    }

    @Override
    public void resetLocalKeystore() {
        try {
            Enumeration<String> elements = this.keyStore.aliases();
            while (elements.hasMoreElements()) {
                this.keyStore.deleteEntry(elements.nextElement());
            }
        } catch (Exception ex) {
        }
    }

    @Override
    public int loadKeypair(String string) {
        try {
            
            // Certificate
            X509Certificate certificate = (X509Certificate) this.keyStore.getCertificate(string);            
            System.out.println(certificate);
            
            // Certificate holder
            JcaX509CertificateHolder certificateHolder = new JcaX509CertificateHolder(certificate);
            String certificateIssuer = ""; 
            if (certificateHolder.getIssuer() != null) {
                certificateIssuer = certificateHolder.getIssuer().toString();
                super.access.setIssuer(certificateIssuer);
                super.access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());
            }
            
            // Version
            super.access.setVersion(2);
            
            // Serial number
            super.access.setSerialNumber(certificate.getSerialNumber().toString());
            
            // Date
            super.access.setNotBefore(certificate.getNotBefore());
            super.access.setNotAfter(certificate.getNotAfter());
            
            // Names
            X500Name subject = certificateHolder.getSubject();
            String certificateSubject = subject.toString();
            
            if (subject.getRDNs(BCStyle.C).length != 0) {
                RDN countryRDN = subject.getRDNs(BCStyle.C)[0];
                String subjectCountry = IETFUtils.valueToString(countryRDN.getFirst().getValue());
                super.access.setSubjectCountry(subjectCountry);
            }
            if (subject.getRDNs(BCStyle.ST).length != 0) {
                RDN stateRDN = subject.getRDNs(BCStyle.ST)[0];
                String subjectState = IETFUtils.valueToString(stateRDN.getFirst().getValue());
                super.access.setSubjectState(subjectState);
            }
            if (subject.getRDNs(BCStyle.L).length != 0) {
                RDN localityRDN = subject.getRDNs(BCStyle.L)[0];
                String subjectLocality = IETFUtils.valueToString(localityRDN.getFirst().getValue());
                super.access.setSubjectLocality(subjectLocality);
            }
            if (subject.getRDNs(BCStyle.O).length != 0) {
                RDN organizationRDN = subject.getRDNs(BCStyle.O)[0];
                String subjectOrganization = IETFUtils.valueToString(organizationRDN.getFirst().getValue());
                super.access.setSubjectOrganization(subjectOrganization);
            }
            if (subject.getRDNs(BCStyle.OU).length != 0) {
                RDN organizationUnitRDN = subject.getRDNs(BCStyle.OU)[0];
                String subjectOrganizationUnit = IETFUtils.valueToString(organizationUnitRDN.getFirst().getValue());
                super.access.setSubjectOrganizationUnit(subjectOrganizationUnit);
            }
            if (subject.getRDNs(BCStyle.CN).length != 0) { 
                RDN commonNameRDN = subject.getRDNs(BCStyle.CN)[0];
                String subjectCommonName = IETFUtils.valueToString(commonNameRDN.getFirst().getValue());
                super.access.setSubjectCommonName(subjectCommonName);
            }
            
            // Extension critical parameteres
            Set<String> criticalExtensions = certificate.getCriticalExtensionOIDs();

            // Extension: key usage
            boolean[] keyUsage; 
            boolean atLeastOne = false;
            try{
                keyUsage = certificate.getKeyUsage();     
                for (boolean b : keyUsage)
                    if(b) atLeastOne = true;
                
                if (atLeastOne) 
                    super.access.setKeyUsage(keyUsage);
                
                if (criticalExtensions.contains(Extension.keyUsage.getId())) 
                    super.access.setCritical(Constants.KU, true);
                else
                    super.access.setCritical(Constants.KU, false);

            } catch(Exception ex) {
            }
            
            // Extension: issuer alternative name
            Collection<List<?>> issuerAlternativeNames;
            
            try {
                issuerAlternativeNames = certificate.getIssuerAlternativeNames();
                String completeStringOfNames = "";
                
                for (List<?> element : issuerAlternativeNames) {
                    String alternativeName = (String) element.get(1);

                    if (element.get(0).toString().equals("0")) {
                        alternativeName = "other=" + alternativeName;
                    } else if (element.get(0).toString().equals("1")) {
                        alternativeName = "rfc822=" + alternativeName;
                    } else if (element.get(0).toString().equals("2")) {
                        alternativeName = "dns=" + alternativeName;
                    } else if (element.get(0).toString().equals("3")) {
                        alternativeName = "x400Address=" + alternativeName;
                    } else if (element.get(0).toString().equals("4")) {
                        alternativeName = "directory=" + alternativeName;
                    } else if (element.get(0).toString().equals("5")) {
                        alternativeName = "ediParty=" + alternativeName;
                    } else if (element.get(0).toString().equals("6")) {
                        alternativeName = "uniformResourceIdentifier=" + alternativeName;
                    } else if (element.get(0).toString().equals("7")) {
                        alternativeName = "ipAddress=" + alternativeName;
                    } else if (element.get(0).toString().equals("8")) {
                        alternativeName = "registeredID=" + alternativeName;
                    }
                    
                    if (completeStringOfNames == "")
                        completeStringOfNames = completeStringOfNames + alternativeName;
                    else 
                        completeStringOfNames = completeStringOfNames + ", " + alternativeName;
                }
                
                super.access.setAlternativeName(Constants.IAN, completeStringOfNames);
                
                if (criticalExtensions.contains(Extension.issuerAlternativeName.getId())) 
                    super.access.setCritical(Constants.IAN, true);
                else
                    super.access.setCritical(Constants.IAN, false);
                
            } catch (Exception ex) {
            }
                            
            // Extension: basic constraints
            int pathLength = certificate.getBasicConstraints();
            String pathLengthString = Integer.toString(pathLength);
            
            if (pathLength == -1) {
                super.access.setCA(false);
            } else {
                super.access.setCA(true);
                super.access.setPathLen(pathLengthString);
            }
            
            if (criticalExtensions.contains(Extension.basicConstraints.getId())) {
                super.access.setCritical(Constants.BC, true);
            } else {
                super.access.setCritical(Constants.BC, false);
            }
            
            // Return value
            //  
            //  -1 - doesn't exist
            //   0 - saved
            //   1 - saved/signed
            //   2 - saved/signed/trusted

            if (this.keyStore.isCertificateEntry(string))
                return 2;
            else if ( !certificateIssuer.equals(certificateSubject) )
                return 1;
            else 
                return 0;

        } catch (Exception ex) {
            return -1;
        } 
    }

    @Override
    public boolean saveKeypair(String string) {
        try {

            // Version check
            int version = super.access.getVersion();
            if (version != 2) {
                Component frame = new Frame();
                JOptionPane.showMessageDialog(frame, "Only v3 is supported!", "Error", JOptionPane.WARNING_MESSAGE);
                return false;
            }

            // Serial number parameter
            String serNum = super.access.getSerialNumber();
            BigInteger serialNumber = new BigInteger(serNum);

            // Date parameters
            Date notBefore = super.access.getNotBefore();
            Date notAfter = super.access.getNotAfter();

            // Key info parameters
            String keyLength = super.access.getPublicKeyParameter();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(Integer.parseInt(keyLength));
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
            
            // Name parameter
            X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            X500Name name;
            String country = super.access.getSubjectCountry();
            String state = super.access.getSubjectState();
            String locality = super.access.getSubjectLocality();
            String organization = super.access.getSubjectOrganization();
            String organizationUnit = super.access.getSubjectOrganizationUnit();
            String commonName = super.access.getSubjectCommonName();
            if (!country.isEmpty()) {
                nameBuilder.addRDN(BCStyle.C, country);
            }
            if (!locality.isEmpty()) {
                nameBuilder.addRDN(BCStyle.L, locality);
            }
            if (!organization.isEmpty()) {
                nameBuilder.addRDN(BCStyle.O, organization);
            }
            if (!organizationUnit.isEmpty()) {
                nameBuilder.addRDN(BCStyle.OU, organizationUnit);
            }
            if (!state.isEmpty()) {
                nameBuilder.addRDN(BCStyle.ST, state);
            }
            if (!commonName.isEmpty()) {
                nameBuilder.addRDN(BCStyle.CN, commonName);
            }
            name = nameBuilder.build();

            // Certificate builder
            X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(name, serialNumber, notBefore, notAfter, name, publicKeyInfo);

            // Extension: key usage
            boolean[] keyUsageArray = super.access.getKeyUsage();
            boolean isKeyUsageCritical = super.access.isCritical(Constants.KU);
            int keyUsageMask = 0;
            KeyUsage keyUsage;
            
            for (int i=0; i< keyUsageArray.length; i++)
                if (keyUsageArray[i]) 
                    switch (i) {
                        case 0: keyUsageMask |= KeyUsage.digitalSignature; break;
                        case 1: keyUsageMask |= KeyUsage.nonRepudiation; break;
                        case 2: keyUsageMask |= KeyUsage.keyEncipherment; break;
                        case 3: keyUsageMask |= KeyUsage.dataEncipherment; break;
                        case 4: keyUsageMask |= KeyUsage.keyAgreement; break;
                        case 5: keyUsageMask |= KeyUsage.keyCertSign; break;
                        case 6: keyUsageMask |= KeyUsage.cRLSign; break;
                        case 7: keyUsageMask |= KeyUsage.encipherOnly; break;
                        case 8: keyUsageMask |= KeyUsage.decipherOnly; break;
                    }
            
            if (keyUsageMask != 0){
                keyUsage = new KeyUsage(keyUsageMask);
                certificateBuilder.addExtension(Extension.keyUsage, isKeyUsageCritical, keyUsage);
            }
            
            // Extension: issuer alternative name
            boolean isIssuerAlternativeNameCritical = super.access.isCritical(Constants.IAN);
            String[] names = super.access.getAlternativeName(Constants.IAN);
            GeneralName[] generalNames = new GeneralName[names.length];
            GeneralNames generalNamesFinal; 
            
            for (int i = 0; i < names.length; i++){
                String[] namesSplit = names[i].split("=");
                if (namesSplit[0].equals("rfc822")) {
                    generalNames[i] = new GeneralName(GeneralName.rfc822Name, namesSplit[1]);
                } else if (namesSplit[0].equals("dns")) {
                    generalNames[i] = new GeneralName(GeneralName.dNSName, namesSplit[1]);
                } else if (namesSplit[0].equals("ediParty")) {
                    generalNames[i] = new GeneralName(GeneralName.ediPartyName, namesSplit[1]);
                } else if (namesSplit[0].equals("ipAddress")) {
                    generalNames[i] = new GeneralName(GeneralName.iPAddress, namesSplit[1]);
                } else if (namesSplit[0].equals("other")) {
                    generalNames[i] = new GeneralName(GeneralName.otherName, namesSplit[1]);
                } else if (namesSplit[0].equals("registeredID")) {
                    generalNames[i] = new GeneralName(GeneralName.registeredID, namesSplit[1]);
                } else if (namesSplit[0].equals("x400Address")) {
                    generalNames[i] = new GeneralName(GeneralName.x400Address, namesSplit[1]);
                } else if (namesSplit[0].equals("directory")) {
                    generalNames[i] = new GeneralName(GeneralName.directoryName, namesSplit[1]);
                } else if (namesSplit[0].equals("uniformResourceIdentifier")) {
                    generalNames[i] = new GeneralName(GeneralName.uniformResourceIdentifier, namesSplit[1]);
                }
            }
            
            generalNamesFinal = new GeneralNames(generalNames);
            if (names.length != 0){
                certificateBuilder.addExtension(Extension.issuerAlternativeName, isIssuerAlternativeNameCritical, generalNamesFinal);
            }
            
            // Extension: basic constraints
            boolean isBasicConstraintsCritical = super.access.isCritical(Constants.BC);
            boolean isCA = super.access.isCA();
            String pathLength = super.access.getPathLen();
            BasicConstraints basicConstraints;
            
            try {
                if (isCA) {
                    basicConstraints = new BasicConstraints(Integer.parseInt(pathLength));
                } else {
                    basicConstraints = new BasicConstraints(false);
                }
                certificateBuilder.addExtension(Extension.basicConstraints, isBasicConstraintsCritical, basicConstraints);
            } catch (Exception e) {
            }
                
            // Content signer
            String algorithm = super.access.getPublicKeyDigestAlgorithm();
            ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(keyPair.getPrivate());

            // Certificate holder and converter
            X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
            JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();

            // Certificate
            X509Certificate certificate = certificateConverter.getCertificate(certificateHolder);
            certificate.verify(keyPair.getPublic());

            System.out.println(certificate);

            // Certificate chain
            X509Certificate[] certificateChain = new X509Certificate[1];
            certificateChain[0] = certificate;
            
            // Adding an entry to the key store:
            
            //      - alias (unique name)
            //      - public key and password to protect it
            //      - chain of certificates to link it with it's private key

            this.keyStore.setKeyEntry(string, keyPair.getPrivate(), "pass".toCharArray(), certificateChain);

            return true;

        } catch (Exception ex) {        
            return false;
        } 
    }

    @Override
    public boolean removeKeypair(String string) {
        try {
            this.keyStore.deleteEntry(string);
            return true;
        } catch (KeyStoreException ex) {
            return false;
        }
    }

    @Override
    public boolean importKeypair(String string, String string1, String string2) {
        try {
            FileInputStream inputStream = new FileInputStream(string1);
            char[] filePath = string1.toCharArray();
            
            if (filePath[filePath.length - 1] != '2' && filePath[filePath.length - 2] != '1' && filePath[filePath.length - 3] != 'p' && filePath[filePath.length - 4] != '.') {
                inputStream.close();
                return false;
            } else {
                KeyStore tempKeyStore = KeyStore.getInstance("PKCS12");
                tempKeyStore.load(inputStream, string2.toCharArray());
                Certificate[] myChain = tempKeyStore.getCertificateChain(string);
                this.keyStore.setKeyEntry(string, tempKeyStore.getKey(string, string2.toCharArray()), "pass".toCharArray(), myChain);
                inputStream.close();            
                return true;
            }          
        } catch (Exception ex) {
        }
        return false;
    }

    @Override
    public boolean exportKeypair(String string, String string1, String string2) {
        OutputStream outputStream;
        File file;
        char[] path = string1.toCharArray();
        if (!(path[path.length - 1] == '2' && path[path.length - 2] == '1' && path[path.length - 3] == 'p' && path[path.length - 4] == '.'))
            string1 = string1 + ".p12";
        try {
            file = new File(string1);
            outputStream = new FileOutputStream(file);
            
            KeyStore tempKeyStore = KeyStore.getInstance("PKCS12");
            tempKeyStore.load(null, null);

            Certificate[] myChain2 = keyStore.getCertificateChain(string);
            tempKeyStore.setKeyEntry(string, this.keyStore.getKey(string, "pass".toCharArray()), string2.toCharArray(), myChain2);
            tempKeyStore.store(outputStream, string2.toCharArray());

            outputStream.close();
            return true;
            
        } catch (Exception ex) {
        } 
       
        return false;
    }

    @Override
    public boolean importCertificate(String string, String string1) {
        
        
        return false;
    }

    @Override
    public boolean exportCertificate(String string, String string1, int i, int i1) {

        Certificate certificate;
        Certificate[] chainOfCertificates;
        Writer writer;
        PemWriter PEMWriter;
        FileOutputStream outputStream;
        char[] filePath = string.toCharArray();
        String filePathWithCer = string;
        
        try {
            certificate = this.keyStore.getCertificate(string1);
            if (!(filePath[filePath.length - 4] == '.' && filePath[filePath.length - 3] == 'c' && filePath[filePath.length - 2] == 'e' && filePath[filePath.length - 1] == 'r'))
                filePathWithCer += ".cer";
            writer = new FileWriter(filePathWithCer);
            
            if (i == 0) {
                byte[] buffer = certificate.getEncoded();
                outputStream = new FileOutputStream(filePathWithCer);
                outputStream.write(buffer);
                outputStream.close();
            } else {
                PEMWriter = new JcaPEMWriter(writer);
                if (i1 == 0){
                    PEMWriter.writeObject((PemObjectGenerator) certificate);
                } else {
                    chainOfCertificates = this.keyStore.getCertificateChain(string1);
                    for (Certificate cert : chainOfCertificates)
                        PEMWriter.writeObject((PemObjectGenerator) cert);
                }
                PEMWriter.flush();
                PEMWriter.close();
            }
            return true;
        } catch (Exception ex) {
            return false;
        }

    }

    @Override
    public boolean exportCSR(String string, String string1, String string2) { 
        
        PKCS10CertificationRequest csr;
        Writer writer;
        PemWriter PEMWriter;
        FileOutputStream outputStream;
        char[] filePath = string.toCharArray();
        String filePathWithCer = string;

        try {
            System.out.println(string); // /Users/nikolamilic/Desktop/borcamilic.csr
            System.out.println(string1);// borca milic
            System.out.println(string2);// SHA1withDSA

            X509Certificate certificate = (X509Certificate) this.keyStore.getCertificate(string1);
            JcaX509CertificateHolder holder = new JcaX509CertificateHolder(certificate);
            X500Name name = holder.getSubject();

            PKCS10CertificationRequestBuilder CSRbuilder = new JcaPKCS10CertificationRequestBuilder(name, certificate.getPublicKey());

            List<ASN1ObjectIdentifier> list = holder.getExtensionOIDs();
            ExtensionsGenerator gen = new ExtensionsGenerator();
            for (ASN1ObjectIdentifier object : list) {
                gen.addExtension(holder.getExtension(object));
            }
            CSRbuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, gen.generate());
            
            JcaContentSignerBuilder contentSigner = new JcaContentSignerBuilder(string2);
            PrivateKey privateKey = (PrivateKey) this.keyStore.getKey(string1, "pass".toCharArray());
            csr = CSRbuilder.build(contentSigner.build(privateKey));
                        
            writer = new FileWriter(filePathWithCer);
            PEMWriter = new JcaPEMWriter(writer);
            PemObjectGenerator objGen = new MiscPEMGenerator(csr);
            PEMWriter.writeObject(objGen);
            PEMWriter.close();
            

            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @Override
    public String importCSR(String string) {
        PKCS10CertificationRequest csr;
        try {
            FileInputStream inputStream = new FileInputStream(string);

            Reader pemReader = new BufferedReader(new InputStreamReader(inputStream));
            PEMParser pemParser = new PEMParser(pemReader);
            Object parsedObj = pemParser.readObject();

            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObj;

                X500Name subject = csr.getSubject();
                return subject.toString();
            }


            return null;
        } catch (Exception ex) {
            return null;
        }
    }

    @Override
    public boolean signCSR(String string, String string1, String string2) {
        
        return false;
    }

    @Override
    public boolean importCAReply(String string, String string1) {
        
        return false;
    }

    @Override
    public boolean canSign(String string) {
        try {
            X509Certificate certificate = (X509Certificate) this.keyStore.getCertificate(string);            
            int pathLength = certificate.getBasicConstraints();
            if (pathLength == -1)
                return false;
            else
                return true;      
        } catch (Exception ex) {
            return false;
        }
    }

    @Override
    public String getSubjectInfo(String string) {
        try {
            X509Certificate certificate = (X509Certificate) this.keyStore.getCertificate(string);
            JcaX509CertificateHolder certificateHolder = new JcaX509CertificateHolder(certificate);
            X500Name subject = certificateHolder.getSubject();
            return subject.toString();
        } catch (Exception ex) {
            return null;
        }
    }

    @Override
    public String getCertPublicKeyAlgorithm(String string) {
        try {
            String algorithm = super.access.getPublicKeyAlgorithm();
            return algorithm;
        } catch (Exception ex) {
            return null;
        }
    }

    @Override
    public String getCertPublicKeyParameter(String string) {
        try {
            String parameter = super.access.getPublicKeyParameter();
            return parameter;
        } catch (Exception ex) {
            return null;
        }   
    }

}
