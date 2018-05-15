package implementation;
import code.GuiException;
import java.util.Enumeration;

public class MyCode extends x509.v3.CodeV3 {

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
    }
    
    @Override
    public Enumeration<String> loadLocalKeystore() {
        return null;
    }

    @Override
    public void resetLocalKeystore() {

    }

    @Override
    public int loadKeypair(String string) {
        return 0;
    }

    @Override
    public boolean saveKeypair(String string) {
        return false;
    }

    @Override
    public boolean removeKeypair(String string) {
        return false;
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
