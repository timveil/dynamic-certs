package io.crdb.docker;

import com.google.common.base.Joiner;
import com.google.common.net.InetAddresses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;
import org.springframework.util.StopWatch;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.*;

@SpringBootApplication
public class DynamicCertsApplication implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DynamicCertsApplication.class);
    private static final String ORGANIZATION_NAME = "Cockroach";

    private enum Outform {
        PEM, DER
    }

    private static final String USE_OPENSSL = "USE_OPENSSL";
    private static final String CLIENT_USERNAME = "CLIENT_USERNAME";
    private static final String NODE_ALTERNATIVE_NAMES = "NODE_ALTERNATIVE_NAMES";

    private static final String DEFAULT_USERNAME = "root";

    private static final String INTERNAL_DIR = "/.cockroach-internal";
    private static final String EXTERNAL_DIR = "/.cockroach-certs";

    private static final String CA_KEY = INTERNAL_DIR + "/ca.key";
    private static final String CA_CERT = EXTERNAL_DIR + "/ca.crt";

    private static final String NODE_CSR = INTERNAL_DIR + "/node.csr";
    private static final String NODE_KEY = EXTERNAL_DIR + "/node.key";
    private static final String NODE_CERT = EXTERNAL_DIR + "/node.crt";


    public static final String CONFIG_CA = "/config/ca.cnf";
    public static final String CONFIG_CSR = "/config/csr.cnf";


    public static void main(String[] args) {
        SpringApplication.run(DynamicCertsApplication.class, args);
    }

    private final Environment env;

    public DynamicCertsApplication(Environment env) {
        this.env = env;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {

        final String nodeNamesString = env.getProperty(NODE_ALTERNATIVE_NAMES);
        final String clientUsername = env.getProperty(CLIENT_USERNAME, DEFAULT_USERNAME);
        final boolean useOpenSSL = env.getProperty(USE_OPENSSL, Boolean.class, false);

        List<String> nodeAlternativeNames = new ArrayList<>();

        if (StringUtils.hasText(nodeNamesString)) {
            nodeAlternativeNames = Arrays.asList(nodeNamesString.trim().split("\\s+"));
        }

        log.info("{} is [{}]", USE_OPENSSL, useOpenSSL);
        log.info("{} is {}", NODE_ALTERNATIVE_NAMES, nodeAlternativeNames);
        log.info("{} is [{}]", CLIENT_USERNAME, clientUsername);

        Set<String> usernames = new HashSet<>();
        usernames.add(clientUsername);

        if (!clientUsername.equals(DEFAULT_USERNAME)) {
            usernames.add(DEFAULT_USERNAME);
        }

        StopWatch sw = new StopWatch();
        sw.start();

        try {

            if (useOpenSSL) {
                createWithOpenSSL(nodeAlternativeNames, usernames);
            } else {
                createWithCockroach(nodeAlternativeNames, usernames);
            }

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        sw.stop();

        log.info("Certificate Generation Complete in {} milliseconds!", sw.getTotalTimeMillis());
    }

    private void createWithOpenSSL(List<String> nodeAlternativeNames, Set<String> usernames) {
        generateKey(CA_KEY, Outform.PEM);

        generateCA();

        handleProcess(new ProcessBuilder("rm", "-f", "/config/index.txt", "/config/serial"));
        handleProcess(new ProcessBuilder("touch", "./config/index.txt"));
        handleProcess(new ProcessBuilder("touch", "./config/serial"));
        handleProcess(new ProcessBuilder("bash", "-c", "echo '01' > /config/serial"));

        // generate node certs...
        generateKey(NODE_KEY, Outform.PEM);

        String subjectAltName = getSubjectAltName(nodeAlternativeNames);

        log.debug("Subject Alt Name = [{}]", subjectAltName);

        generateCSR(NODE_CSR, NODE_KEY, null, subjectAltName);

        generateCertificate(NODE_CERT, NODE_CSR);


        // generate client certs...
        for (String username : usernames) {
            String clientKeyPEM = EXTERNAL_DIR + String.format("/client.%s.key", username.toLowerCase());
            String clientKeyDER = EXTERNAL_DIR + String.format("/client.%s.der", username.toLowerCase());
            String clientCsr = INTERNAL_DIR + String.format("/client.%s.csr", username.toLowerCase());
            String clientCrt = EXTERNAL_DIR + String.format("/client.%s.crt", username.toLowerCase());
            String clientP12 = EXTERNAL_DIR + String.format("/client.%s.p12", username.toLowerCase());

            generateKey(clientKeyPEM, Outform.PEM);
            generateKey(clientKeyDER, Outform.DER);
            generateCSR(clientCsr, clientKeyPEM, username, String.format("DNS:%s", username));
            generateCertificate(clientCrt, clientCsr);
            generateP12(clientP12, clientCrt, clientKeyPEM);
        }

    }

    private String getSubjectAltName(List<String> nodeAlternativeNames) {
        Set<String> names = new HashSet<>();
        names.add("DNS:node");

        for (String altName : nodeAlternativeNames) {

            altName = StringUtils.trimWhitespace(altName);

            if (StringUtils.hasText(altName)) {
                if (InetAddresses.isInetAddress(altName)) {
                    altName = "IP:" + altName;
                } else {
                    altName = "DNS:" + altName;
                }
                names.add(altName);
            }
        }

        return Joiner.on(",").skipNulls().join(names);
    }

    private void generateCA() {
        List<String> commands = new ArrayList<>();
        commands.add("openssl");
        commands.add("req");
        commands.add("-verbose");
        commands.add("-new");
        commands.add("-x509");
        commands.add("-config");
        commands.add(CONFIG_CA);
        commands.add("-key");
        commands.add(CA_KEY);
        commands.add("-out");
        commands.add(CA_CERT);
        commands.add("-days");
        commands.add("365");
        commands.add("-batch");

        handleProcess(new ProcessBuilder(commands));
    }

    private void generateCertificate(String out, String in) {
        List<String> commands = new ArrayList<>();
        commands.add("openssl");
        commands.add("ca");
        commands.add("-verbose");
        commands.add("-config");
        commands.add(CONFIG_CA);
        commands.add("-keyfile");
        commands.add(CA_KEY);
        commands.add("-cert");
        commands.add(CA_CERT);
        commands.add("-policy");
        commands.add("signing_policy");
        commands.add("-extensions");
        commands.add("signing_node_req");
        commands.add("-out");
        commands.add(out);
        commands.add("-outdir");
        commands.add(EXTERNAL_DIR);
        commands.add("-in");
        commands.add(in);
        commands.add("-batch");

        handleProcess(new ProcessBuilder(commands));
    }

    private void generateCSR(String out, String key, String commonName, String subjectAltName) {
        StringBuilder distinguishedName = new StringBuilder();
        distinguishedName.append("/O=");
        distinguishedName.append(ORGANIZATION_NAME);

        if (StringUtils.hasText(commonName)) {
            distinguishedName.append("/CN=");
            distinguishedName.append(commonName);
        }

        List<String> commands = new ArrayList<>();
        commands.add("openssl");
        commands.add("req");
        commands.add("-verbose");
        commands.add("-new");
        commands.add("-config");
        commands.add(CONFIG_CSR);
        commands.add("-subj");
        commands.add(String.format("%s", distinguishedName));
        commands.add("-addext");
        commands.add(String.format("subjectAltName=%s", subjectAltName));
        commands.add("-key");
        commands.add(key);
        commands.add("-out");
        commands.add(out);
        commands.add("-batch");

        handleProcess(new ProcessBuilder(commands));
    }

    private void generateKey(String out, Outform outform) {
        List<String> commands = new ArrayList<>();
        commands.add("openssl");
        commands.add("genpkey");
        commands.add("-quiet");
        commands.add("-outform");
        commands.add(outform.name());
        commands.add("-algorithm");
        commands.add("RSA");
        commands.add("-out");
        commands.add(out);

        handleProcess(new ProcessBuilder(commands));

        handleProcess(new ProcessBuilder("chmod", "400", out));

    }

    private void generateP12(String out, String inCert, String inKey) {
        List<String> commands = new ArrayList<>();
        commands.add("openssl");
        commands.add("pkcs12");
        commands.add("-export");
        commands.add("-out");
        commands.add(out);
        commands.add("-inkey");
        commands.add(inKey);
        commands.add("-in");
        commands.add(inCert);
        commands.add("-passout");
        commands.add("pass:password"); //todo: make dynamic


        handleProcess(new ProcessBuilder(commands));

        handleProcess(new ProcessBuilder("chmod", "600", out));
    }

    private void createWithCockroach(List<String> nodeAlternativeNames, Set<String> usernames) {
        List<String> createCACommands = new ArrayList<>();
        createCACommands.add("/cockroach");
        createCACommands.add("cert");
        createCACommands.add("create-ca");
        createCACommands.add("--certs-dir");
        createCACommands.add(EXTERNAL_DIR);
        createCACommands.add("--ca-key");
        createCACommands.add(CA_KEY);

        handleProcess(new ProcessBuilder(createCACommands));

        for (String username : usernames) {
            List<String> createClientCommands = new ArrayList<>();
            createClientCommands.add("/cockroach");
            createClientCommands.add("cert");
            createClientCommands.add("create-client");
            createClientCommands.add(username);
            createClientCommands.add("--certs-dir");
            createClientCommands.add(EXTERNAL_DIR);
            createClientCommands.add("--ca-key");
            createClientCommands.add(CA_KEY);
            createClientCommands.add("--also-generate-pkcs8-key");

            handleProcess(new ProcessBuilder(createClientCommands));
        }


        List<String> createNodeCommands = new ArrayList<>();
        createNodeCommands.add("/cockroach");
        createNodeCommands.add("cert");
        createNodeCommands.add("create-node");
        createNodeCommands.addAll(nodeAlternativeNames);
        createNodeCommands.add("--certs-dir");
        createNodeCommands.add(EXTERNAL_DIR);
        createNodeCommands.add("--ca-key");
        createNodeCommands.add(CA_KEY);

        handleProcess(new ProcessBuilder(createNodeCommands));
    }

    private void handleProcess(ProcessBuilder builder) {

        String command = builder.command().toString();

        log.debug("starting command... {}", command);

        Process process = null;

        try {
            process = builder.start();

            int exitCode = process.waitFor();

            String is = new String(process.getInputStream().readAllBytes());

            if (StringUtils.hasText(is)) {
                log.info("input stream:\n\n{}", is);
            }

            String es = new String(process.getErrorStream().readAllBytes());

            if (StringUtils.hasText(es)) {
                log.error("error stream:\n\n{}", es);
            }

            if (exitCode != 0) {
                throw new RuntimeException(String.format("the following command exited ABNORMALLY with code [%d]: %s", exitCode, command));
            } else {
                log.debug("command exited SUCCESSFULLY with code [{}]", exitCode);
            }

        } catch (IOException | InterruptedException e) {
            log.error(e.getMessage(), e);
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }
}
