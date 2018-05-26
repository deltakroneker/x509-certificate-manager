package implementation;

import code.GuiException;
import gui.Constants;
import java.awt.Component;
import java.awt.Frame;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;
import java.security.*;
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
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.Extensions.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.*;
import static org.bouncycastle.asn1.x509.X509Extensions.IssuerAlternativeName;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import sun.security.jca.JCAUtil;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.EDIPartyName;
import sun.security.x509.IssuerAlternativeNameExtension;
import x509.v3.GuiV3;

public class MyCode extends x509.v3.CodeV3 {

    private KeyStore keyStore;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        Security.addProvider(new BouncyCastleProvider());
        try {
            this.keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            return (this.keyStore == null) ? null : this.keyStore.aliases();
        } catch (KeyStoreException ex) {
        } catch (IOException ex) {
        } catch (NoSuchAlgorithmException ex) {
        } catch (CertificateException ex) {
        } finally {
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
        } catch (KeyStoreException ex) {
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
                this.access.setIssuer(certificateIssuer);
                this.access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());
            }
            
            // Version
            this.access.setVersion(2);
            
            // Serial number
            this.access.setSerialNumber(certificate.getSerialNumber().toString());
            
            // Date
            this.access.setNotBefore(certificate.getNotBefore());
            this.access.setNotAfter(certificate.getNotAfter());
            
            // Names
            X500Name subject = certificateHolder.getSubject();
            String certificateSubject = subject.toString();
            
            if (subject.getRDNs(BCStyle.C).length != 0) {
                RDN countryRDN = subject.getRDNs(BCStyle.C)[0];
                String subjectCountry = IETFUtils.valueToString(countryRDN.getFirst().getValue());
                this.access.setSubjectCountry(subjectCountry);
            }
            if (subject.getRDNs(BCStyle.ST).length != 0) {
                RDN stateRDN = subject.getRDNs(BCStyle.ST)[0];
                String subjectState = IETFUtils.valueToString(stateRDN.getFirst().getValue());
                this.access.setSubjectState(subjectState);
            }
            if (subject.getRDNs(BCStyle.L).length != 0) {
                RDN localityRDN = subject.getRDNs(BCStyle.L)[0];
                String subjectLocality = IETFUtils.valueToString(localityRDN.getFirst().getValue());
                this.access.setSubjectLocality(subjectLocality);
            }
            if (subject.getRDNs(BCStyle.O).length != 0) {
                RDN organizationRDN = subject.getRDNs(BCStyle.O)[0];
                String subjectOrganization = IETFUtils.valueToString(organizationRDN.getFirst().getValue());
                this.access.setSubjectOrganization(subjectOrganization);
            }
            if (subject.getRDNs(BCStyle.OU).length != 0) {
                RDN organizationUnitRDN = subject.getRDNs(BCStyle.OU)[0];
                String subjectOrganizationUnit = IETFUtils.valueToString(organizationUnitRDN.getFirst().getValue());
                this.access.setSubjectOrganizationUnit(subjectOrganizationUnit);
            }
            if (subject.getRDNs(BCStyle.CN).length != 0) { 
                RDN commonNameRDN = subject.getRDNs(BCStyle.CN)[0];
                String subjectCommonName = IETFUtils.valueToString(commonNameRDN.getFirst().getValue());
                this.access.setSubjectCommonName(subjectCommonName);
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
                    this.access.setKeyUsage(keyUsage);
                
                if (criticalExtensions.contains(Extension.keyUsage.getId())) 
                    this.access.setCritical(Constants.KU, true);
                else
                    this.access.setCritical(Constants.KU, false);

            } catch(Exception e) {
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
                
                this.access.setAlternativeName(Constants.IAN, completeStringOfNames);
                
                if (criticalExtensions.contains(Extension.issuerAlternativeName.getId())) 
                    this.access.setCritical(Constants.IAN, true);
                else
                    this.access.setCritical(Constants.IAN, false);
                
            } catch (CertificateParsingException ex) {
            }
                            
            // Extension: basic constraints
            int pathLength = certificate.getBasicConstraints();
            String pathLengthString = Integer.toString(pathLength);
            
            if (pathLength == -1) {
                this.access.setCA(false);
            } else {
                this.access.setCA(true);
                this.access.setPathLen(pathLengthString);
            }
            
            if (criticalExtensions.contains(Extension.basicConstraints.getId())) {
                this.access.setCritical(Constants.BC, true);
            } else {
                this.access.setCritical(Constants.BC, false);
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

        } catch (KeyStoreException ex) {
        } catch (CertificateEncodingException ex) {
        }
        
        return -1;
    }

    @Override
    public boolean saveKeypair(String string) {
        try {

            // Version check
            int version = this.access.getVersion();
            if (version != 2) {
                Component frame = new Frame();
                JOptionPane.showMessageDialog(frame, "Only v3 is supported!", "Error", JOptionPane.WARNING_MESSAGE);
                return false;
            }

            // Serial number parameter
            String serNum = this.access.getSerialNumber();
            BigInteger serialNumber = new BigInteger(serNum);

            // Date parameters
            Date notBefore = this.access.getNotBefore();
            Date notAfter = this.access.getNotAfter();

            // Key info parameters
            String keyLength = this.access.getPublicKeyParameter();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(Integer.parseInt(keyLength));
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
            
            // Name parameter
            X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            X500Name name;
            String country = this.access.getSubjectCountry();
            String state = this.access.getSubjectState();
            String locality = this.access.getSubjectLocality();
            String organization = this.access.getSubjectOrganization();
            String organizationUnit = this.access.getSubjectOrganizationUnit();
            String commonName = this.access.getSubjectCommonName();
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
            boolean[] keyUsageArray = this.access.getKeyUsage();
            boolean isKeyUsageCritical = this.access.isCritical(Constants.KU);
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
            boolean isIssuerAlternativeNameCritical = this.access.isCritical(Constants.IAN);
            String[] names = this.access.getAlternativeName(Constants.IAN);
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
            boolean isBasicConstraintsCritical = this.access.isCritical(Constants.BC);
            boolean isCA = this.access.isCA();
            String pathLength = this.access.getPathLen();
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
            String algorithm = this.access.getPublicKeyDigestAlgorithm();
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

            this.keyStore.setKeyEntry(string, keyPair.getPrivate(), null, certificateChain);

            return true;

        } catch (NoSuchAlgorithmException ex) {
        } catch (IllegalStateException ex) {
        } catch (OperatorCreationException ex) {
        } catch (CertificateException ex) {
        } catch (InvalidKeyException ex) {
        } catch (NoSuchProviderException ex) {
        } catch (SignatureException ex) {
        } catch (KeyStoreException ex) { 
        } catch (CertIOException ex) {
        }
        
        return false;
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
        return false;
    }

    @Override
    public boolean exportKeypair(String string, String string1, String string2) {
        return false;
    }

    @Override
    public boolean importCertificate(String string, String string1) {
        return false;
    }

    @Override
    public boolean exportCertificate(String string, String string1, int i, int i1) {
        return false;
    }

    @Override
    public boolean exportCSR(String string, String string1, String string2) {
        return false;
    }

    @Override
    public String importCSR(String string) {
        return null;
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
        return false;
    }

    @Override
    public String getSubjectInfo(String string) {
        return null;
    }

    @Override
    public String getCertPublicKeyAlgorithm(String string) {
        return null;
    }

    @Override
    public String getCertPublicKeyParameter(String string) {
        return null;
    }

}
