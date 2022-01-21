package io.crdb.docker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.*;

@SpringBootApplication
public class DynamicCertsApplication implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DynamicCertsApplication.class);

    private static final String USE_OPENSSL = "USE_OPENSSL";
    private static final String CLIENT_USERNAME = "CLIENT_USERNAME";
    private static final String NODE_ALTERNATIVE_NAMES = "NODE_ALTERNATIVE_NAMES";

    private static final String DEFAULT_USERNAME = "root";

    private static final String COCKROACH_INTERNAL_DIR = "/.cockroach-internal";
    private static final String COCKROACH_EXTERNAL_DIR = "/.cockroach-certs";

    private static final String COCKROACH_CA_KEY = COCKROACH_INTERNAL_DIR + "/ca.key";
    private static final String COCKROACH_CA_CERT = COCKROACH_EXTERNAL_DIR + "/ca.crt";

    private static final String COCKROACH_NODE_CSR = COCKROACH_INTERNAL_DIR + "/node.csr";
    private static final String COCKROACH_NODE_KEY = COCKROACH_EXTERNAL_DIR + "/node.key";
    private static final String COCKROACH_NODE_CERT = COCKROACH_EXTERNAL_DIR + "/node.crt";

    private static final String COCKROACH_CLIENT_ROOT_CSR = COCKROACH_INTERNAL_DIR + "/client.root.csr";
    private static final String COCKROACH_CLIENT_ROOT_KEY = COCKROACH_EXTERNAL_DIR + "/client.root.key";
    private static final String COCKROACH_CLIENT_ROOT_CERT = COCKROACH_EXTERNAL_DIR + "/client.root.crt";
    private static final String COCKROACH_CLIENT_ROOT_P12 = COCKROACH_EXTERNAL_DIR + "/client.p12";

    public static final String CONFIG_CA = "/config/ca.cnf";
    public static final String CONFIG_CLIENT_ROOT = "/config/client.root.cnf";
    public static final String CONFIG_NODE = "/config/node.cnf";


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
        log.info("{} is [{}]", NODE_ALTERNATIVE_NAMES, nodeAlternativeNames);
        log.info("{} is [{}]", CLIENT_USERNAME, clientUsername);

        Set<String> usernames = new HashSet<>();
        usernames.add(clientUsername);

        if (!clientUsername.equals(DEFAULT_USERNAME)){
            usernames.add(DEFAULT_USERNAME);
        }

        try {
            if (useOpenSSL) {
                createWithOpenSSL(nodeAlternativeNames, usernames);
            } else {
                createWithCockroach(nodeAlternativeNames, usernames);
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    private void createWithOpenSSL(List<String> nodeAlternativeNames, Set<String> usernames) throws IOException, InterruptedException {
        generateKey(COCKROACH_CA_KEY, false);

        List<String> createCACertCommands = new ArrayList<>();
        createCACertCommands.add("openssl");
        createCACertCommands.add("req");
        createCACertCommands.add("-new");
        createCACertCommands.add("-x509");
        createCACertCommands.add("-config");
        createCACertCommands.add(CONFIG_CA);
        createCACertCommands.add("-key");
        createCACertCommands.add(COCKROACH_CA_KEY);
        createCACertCommands.add("-out");
        createCACertCommands.add(COCKROACH_CA_CERT);
        createCACertCommands.add("-days");
        createCACertCommands.add("365");
        createCACertCommands.add("-batch");

        handleProcess(new ProcessBuilder(createCACertCommands));

        handleProcess(new ProcessBuilder("rm", "-f", "/config/index.txt", "/config/serial"));
        handleProcess(new ProcessBuilder("touch", "./config/index.txt"));
        handleProcess(new ProcessBuilder("touch", "./config/serial"));
        handleProcess(new ProcessBuilder("bash", "-c", "echo '01' > /config/serial"));

        // generate node certs...

        generateKey(COCKROACH_NODE_KEY, false);

        generateCSR(CONFIG_NODE, COCKROACH_NODE_KEY, COCKROACH_NODE_CSR);

        generateCertificate(COCKROACH_NODE_CERT, COCKROACH_NODE_CSR);


        // generate client certs...

        generateKey(COCKROACH_CLIENT_ROOT_KEY, true);

        generateCSR(CONFIG_CLIENT_ROOT, COCKROACH_CLIENT_ROOT_KEY, COCKROACH_CLIENT_ROOT_CSR);

        generateCertificate(COCKROACH_CLIENT_ROOT_CERT, COCKROACH_CLIENT_ROOT_CSR);

        generateP12(COCKROACH_CLIENT_ROOT_P12, COCKROACH_CLIENT_ROOT_CERT, COCKROACH_CLIENT_ROOT_KEY);

    }

    private void generateCertificate(String out, String in) throws IOException, InterruptedException {
        List<String> commands = new ArrayList<>();
        commands.add("openssl");
        commands.add("ca");
        commands.add("-config");
        commands.add(CONFIG_CA);
        commands.add("-keyfile");
        commands.add(COCKROACH_CA_KEY);
        commands.add("-cert");
        commands.add(COCKROACH_CA_CERT);
        commands.add("-policy");
        commands.add("signing_policy");
        commands.add("-extensions");
        commands.add("signing_node_req");
        commands.add("-out");
        commands.add(out);
        commands.add("-outdir");
        commands.add(COCKROACH_EXTERNAL_DIR);
        commands.add("-in");
        commands.add(in);
        commands.add("-batch");

        handleProcess(new ProcessBuilder(commands));
    }

    private void generateCSR(String config, String key, String out) throws IOException, InterruptedException {
        List<String> commands = new ArrayList<>();
        commands.add("openssl");
        commands.add("req");
        commands.add("-new");
        commands.add("-config");
        commands.add(config);
        commands.add("-key");
        commands.add(key);
        commands.add("-out");
        commands.add(out);
        commands.add("-batch");

        handleProcess(new ProcessBuilder(commands));
    }

    private void generateKey(String out, boolean generatePK8) throws IOException, InterruptedException {
        List<String> commands = new ArrayList<>();
        commands.add("openssl");
        commands.add("genrsa");
        commands.add("-out");
        commands.add(out);
        commands.add("2048");

        handleProcess(new ProcessBuilder(commands));

        handleProcess(new ProcessBuilder("chmod", "400", out));

        // generates PK8 file in DER format
        if (generatePK8) {

            String pk8Out = out + ".pk8";

            List<String> pkcs8Commands = new ArrayList<>();
            pkcs8Commands.add("openssl");
            pkcs8Commands.add("pkcs8");
            pkcs8Commands.add("-topk8");
            pkcs8Commands.add("-inform");
            pkcs8Commands.add("PEM");
            pkcs8Commands.add("-outform");
            pkcs8Commands.add("DER");
            pkcs8Commands.add("-nocrypt");
            pkcs8Commands.add("-in");
            pkcs8Commands.add(out);
            pkcs8Commands.add("-out");
            pkcs8Commands.add(pk8Out);

            handleProcess(new ProcessBuilder(pkcs8Commands));

            handleProcess(new ProcessBuilder("chmod", "400", pk8Out));
        }

    }

    private void generateP12(String out, String inCert, String inKey) throws IOException, InterruptedException {
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

    private void createWithCockroach(List<String> nodeAlternativeNames, Set<String> usernames) throws IOException, InterruptedException {
        List<String> createCACommands = new ArrayList<>();
        createCACommands.add("/cockroach");
        createCACommands.add("cert");
        createCACommands.add("create-ca");
        createCACommands.add("--certs-dir");
        createCACommands.add(COCKROACH_EXTERNAL_DIR);
        createCACommands.add("--ca-key");
        createCACommands.add(COCKROACH_CA_KEY);

        handleProcess(new ProcessBuilder(createCACommands));

        for (String username : usernames) {
            List<String> createClientCommands = new ArrayList<>();
            createClientCommands.add("/cockroach");
            createClientCommands.add("cert");
            createClientCommands.add("create-client");
            createClientCommands.add(username);
            createClientCommands.add("--certs-dir");
            createClientCommands.add(COCKROACH_EXTERNAL_DIR);
            createClientCommands.add("--ca-key");
            createClientCommands.add(COCKROACH_CA_KEY);
            createClientCommands.add("--also-generate-pkcs8-key");

            handleProcess(new ProcessBuilder(createClientCommands));
        }


        List<String> createNodeCommands = new ArrayList<>();
        createNodeCommands.add("/cockroach");
        createNodeCommands.add("cert");
        createNodeCommands.add("create-node");
        createNodeCommands.addAll(nodeAlternativeNames);
        createNodeCommands.add("--certs-dir");
        createNodeCommands.add(COCKROACH_EXTERNAL_DIR);
        createNodeCommands.add("--ca-key");
        createNodeCommands.add(COCKROACH_CA_KEY);

        handleProcess(new ProcessBuilder(createNodeCommands));
    }

    private void handleProcess(ProcessBuilder builder) throws IOException, InterruptedException {

        builder.inheritIO();

        String command = builder.command().toString();

        log.debug("starting command... {}", command);

        Process process = builder.start();
        int exitCode = process.waitFor();

        if (exitCode != 0) {
            throw new RuntimeException(String.format("the following command exited ABNORMALLY with code [%d]: %s", exitCode, command));
        } else {
            log.debug("command exited SUCCESSFULLY with code [{}]", exitCode);
        }

    }
}
