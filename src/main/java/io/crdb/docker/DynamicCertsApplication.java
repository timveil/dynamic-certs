package io.crdb.docker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;

import java.io.IOException;
import java.util.*;

@SpringBootApplication
public class DynamicCertsApplication implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DynamicCertsApplication.class);

    private static final String USE_OPENSSL = "USE_OPENSSL";
    private static final String CLIENT_USERNAME = "CLIENT_USERNAME";
    private static final String NODE_ALTERNATIVE_NAMES = "NODE_ALTERNATIVE_NAMES";
    private static final String DEFAULT_USERNAME = "root";

    private static final String COCKROACH_KEY_DIR = "/.cockroach-key";
    private static final String COCKROACH_CERTS_DIR = "/.cockroach-certs";

    private static final String COCKROACH_CA_KEY = COCKROACH_KEY_DIR + "/ca.key";
    private static final String COCKROACH_CA_CERT = COCKROACH_CERTS_DIR + "/ca.crt";

    private static final String COCKROACH_NODE_KEY = COCKROACH_KEY_DIR + "/node.key";
    private static final String COCKROACH_NODE_CSR = COCKROACH_CERTS_DIR + "/node.csr";
    private static final String COCKROACH_NODE_CERT = COCKROACH_CERTS_DIR + "/node.crt";

    private static final String COCKROACH_CLIENT_ROOT_KEY = COCKROACH_KEY_DIR + "/client.root.key";
    private static final String COCKROACH_CLIENT_ROOT_CSR = COCKROACH_CERTS_DIR + "/client.root.csr";
    private static final String COCKROACH_CLIENT_ROOT_CERT = COCKROACH_CERTS_DIR + "/client.root.crt";


    public static void main(String[] args) {
        SpringApplication.run(DynamicCertsApplication.class, args);
    }

    private final Environment env;

    public DynamicCertsApplication(Environment env) {
        this.env = env;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {

        final List<String> nodeAlternativeNames = Arrays.asList(env.getRequiredProperty(NODE_ALTERNATIVE_NAMES).trim().split("\\s+"));
        final String clientUsername = env.getProperty(CLIENT_USERNAME, DEFAULT_USERNAME);
        final boolean useOpenSSL = env.getProperty(USE_OPENSSL, Boolean.class, false);

        log.info("{} is [{}]", USE_OPENSSL, useOpenSSL);
        log.info("{} is [{}]", NODE_ALTERNATIVE_NAMES, nodeAlternativeNames);
        log.info("{} is [{}]", CLIENT_USERNAME, clientUsername);

        Set<String> usernames = new HashSet<>();
        usernames.add(clientUsername);

        if (!clientUsername.equals(DEFAULT_USERNAME)){
            usernames.add(DEFAULT_USERNAME);
        }

        if (useOpenSSL) {
            createWithOpenSSL(nodeAlternativeNames, usernames);
        } else {
            createWithCockroach(nodeAlternativeNames, usernames);
        }
    }

    private void createWithOpenSSL(List<String> nodeAlternativeNames, Set<String> usernames) throws IOException, InterruptedException {
        generateKey(COCKROACH_CA_KEY);

        handleProcess(new ProcessBuilder("chmod", "400", COCKROACH_CA_KEY));

        List<String> createCACertCommands = new ArrayList<>();
        createCACertCommands.add("openssl");
        createCACertCommands.add("req");
        createCACertCommands.add("-new");
        createCACertCommands.add("-x509");
        createCACertCommands.add("-config");
        createCACertCommands.add("ca.cnf");
        createCACertCommands.add("-key");
        createCACertCommands.add(COCKROACH_CA_KEY);
        createCACertCommands.add("-out");
        createCACertCommands.add(COCKROACH_CA_CERT);
        createCACertCommands.add("-days");
        createCACertCommands.add("365");
        createCACertCommands.add("-batch");

        handleProcess(new ProcessBuilder(createCACertCommands));

        handleProcess(new ProcessBuilder("rm", "-f", "index.txt", "serial.txt"));
        handleProcess(new ProcessBuilder("touch", "index.txt"));
        handleProcess(new ProcessBuilder("echo", "'01'", ">", "serial.txt"));

        // generate node certs...

        generateKey(COCKROACH_NODE_KEY);

        generateCSR("node.cnf", COCKROACH_NODE_KEY, COCKROACH_NODE_CSR);

        generateCertificate(COCKROACH_NODE_CERT, COCKROACH_NODE_CSR);


        // generate client certs...

        generateKey(COCKROACH_CLIENT_ROOT_KEY);

        generateCSR("client.root.cnf", COCKROACH_CLIENT_ROOT_KEY, COCKROACH_CLIENT_ROOT_CSR);

        generateCertificate(COCKROACH_CLIENT_ROOT_CERT, COCKROACH_CLIENT_ROOT_CSR);

    }

    private void generateCertificate(String out, String in) throws IOException, InterruptedException {
        List<String> commands = new ArrayList<>();
        commands.add("openssl");
        commands.add("ca");
        commands.add("-config");
        commands.add("ca.cnf");
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
        commands.add(COCKROACH_CERTS_DIR);
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

    private void generateKey(String out) throws IOException, InterruptedException {
        List<String> commands = new ArrayList<>();
        commands.add("openssl");
        commands.add("genrsa");
        commands.add("-out");
        commands.add(out);
        commands.add("2048");

        handleProcess(new ProcessBuilder(commands));

        handleProcess(new ProcessBuilder("chmod", "400", out));

    }

    private void createWithCockroach(List<String> nodeAlternativeNames, Set<String> usernames) throws IOException, InterruptedException {
        List<String> createCACommands = new ArrayList<>();
        createCACommands.add("/cockroach");
        createCACommands.add("cert");
        createCACommands.add("create-ca");
        createCACommands.add("--certs-dir");
        createCACommands.add(COCKROACH_CERTS_DIR);
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
            createClientCommands.add(COCKROACH_CERTS_DIR);
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
        createNodeCommands.add(COCKROACH_CERTS_DIR);
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
