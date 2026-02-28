/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.headless;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.xebyte.core.JsonHelper;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.ClientAuthenticator;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.remote.AnonymousCallback;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.remote.SSHSignatureCallback;
import ghidra.framework.remote.User;
import ghidra.framework.store.CheckoutType;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;

import javax.security.auth.callback.*;
import java.util.HashMap;
import java.util.Map;
import java.io.IOException;
import java.net.Authenticator;

/**
 * Manages connections to a shared Ghidra repository server.
 *
 * Provides connectivity to a Ghidra server for centralized analysis storage
 * and team collaboration. Configuration is driven by environment variables:
 *
 * <ul>
 *   <li>GHIDRA_SERVER_HOST - Server hostname (default: localhost)</li>
 *   <li>GHIDRA_SERVER_PORT - Server port (default: 13100)</li>
 *   <li>GHIDRA_SERVER_USER - Service account username (required for auth)</li>
 *   <li>GHIDRA_SERVER_PASSWORD - Service account password (required for auth)</li>
 * </ul>
 */
public class GhidraServerManager {

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 13100;

    private final String host;
    private final int port;
    private final String user;
    private final char[] password;

    private RepositoryServerAdapter serverAdapter;
    private final Map<String, RepositoryAdapter> repositoryCache = new HashMap<>();
    private volatile boolean connected = false;
    private String lastError;
    private static volatile boolean authenticatorRegistered = false;

    public GhidraServerManager() {
        this.host = getEnvOrDefault("GHIDRA_SERVER_HOST", DEFAULT_HOST);
        this.port = parsePort(System.getenv("GHIDRA_SERVER_PORT"), DEFAULT_PORT);
        this.user = System.getenv("GHIDRA_SERVER_USER");
        String pwd = System.getenv("GHIDRA_SERVER_PASSWORD");
        this.password = (pwd != null) ? pwd.toCharArray() : null;
        registerAuthenticator();
    }

    public GhidraServerManager(String host, int port, String user, String password) {
        this.host = (host != null && !host.isEmpty()) ? host : DEFAULT_HOST;
        this.port = port > 0 ? port : DEFAULT_PORT;
        this.user = user;
        this.password = (password != null) ? password.toCharArray() : null;
        registerAuthenticator();
    }

    private synchronized void registerAuthenticator() {
        if (authenticatorRegistered) return;
        if (user != null && password != null) {
            try {
                ClientUtil.setClientAuthenticator(new GhidraMCPAuthenticator(user, password));
                authenticatorRegistered = true;
                System.out.println("Registered GhidraMCP authenticator for user: " + user);
            } catch (Exception e) {
                System.err.println("Failed to register authenticator: " + e.getMessage());
            }
        } else {
            System.out.println("No credentials configured - server connection will use anonymous/default auth");
        }
    }

    public synchronized String connect() {
        if (connected && serverAdapter != null && serverAdapter.isConnected()) {
            JsonObject obj = new JsonObject();
            obj.addProperty("status", "already_connected");
            obj.addProperty("host", host);
            obj.addProperty("port", port);
            obj.addProperty("user", user);
            return JsonHelper.toJson(obj);
        }
        if (user == null || password == null) {
            lastError = "Credentials not configured. Set GHIDRA_SERVER_USER and GHIDRA_SERVER_PASSWORD";
            return statusError(lastError);
        }
        try {
            System.out.println("Connecting to Ghidra server at " + host + ":" + port + " as " + user);
            serverAdapter = ClientUtil.getRepositoryServer(host, port);
            serverAdapter.connect();
            connected = serverAdapter.isConnected();
            lastError = null;
            if (connected) {
                System.out.println("Connected to Ghidra server at " + host + ":" + port + " as " + user);
                JsonObject obj = new JsonObject();
                obj.addProperty("status", "connected");
                obj.addProperty("host", host);
                obj.addProperty("port", port);
                obj.addProperty("user", user);
                return JsonHelper.toJson(obj);
            } else {
                lastError = "Connection returned but server reports not connected";
                return statusError(lastError);
            }
        } catch (Exception e) {
            connected = false;
            lastError = e.getMessage();
            System.err.println("Failed to connect to Ghidra server at " + host + ":" + port + " - " + e.getMessage());
            e.printStackTrace();
            JsonObject obj = new JsonObject();
            obj.addProperty("status", "error");
            obj.addProperty("error", lastError);
            obj.addProperty("host", host);
            obj.addProperty("port", port);
            return JsonHelper.toJson(obj);
        }
    }

    public synchronized String disconnect() {
        if (!connected || serverAdapter == null) {
            return statusJson("not_connected");
        }
        try {
            serverAdapter.disconnect();
            connected = false;
            serverAdapter = null;
            lastError = null;
            System.out.println("Disconnected from Ghidra server");
            return statusJson("disconnected");
        } catch (Exception e) {
            lastError = e.getMessage();
            connected = false;
            serverAdapter = null;
            return statusError(lastError);
        }
    }

    public String getStatus() {
        JsonObject obj = new JsonObject();
        obj.addProperty("connected", connected);
        obj.addProperty("host", host);
        obj.addProperty("port", port);
        if (user != null && !user.isEmpty()) {
            obj.addProperty("user", user);
        }
        obj.addProperty("credentials_configured", user != null && password != null);
        if (connected && serverAdapter != null) {
            obj.addProperty("server_connected", serverAdapter.isConnected());
        }
        if (lastError != null) {
            obj.addProperty("last_error", lastError);
        }
        return JsonHelper.toJson(obj);
    }

    public String listRepositories() {
        String err = requireConnection();
        if (err != null) return err;
        try {
            String[] repoNames = serverAdapter.getRepositoryNames();
            JsonObject obj = new JsonObject();
            JsonArray arr = new JsonArray();
            for (String name : repoNames) arr.add(name);
            obj.add("repositories", arr);
            obj.addProperty("count", repoNames.length);
            return JsonHelper.toJson(obj);
        } catch (IOException e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Failed to list repositories: " + e.getMessage());
        }
    }

    private RepositoryAdapter getRepository(String repoName) throws IOException {
        if (!connected || serverAdapter == null) {
            throw new IOException("Not connected to server");
        }
        RepositoryAdapter repo = repositoryCache.get(repoName);
        if (repo == null || !repo.isConnected()) {
            repo = serverAdapter.getRepository(repoName);
            if (repo != null) {
                repo.connect();
                repositoryCache.put(repoName, repo);
            }
        }
        return repo;
    }

    public String listRepositoryFiles(String repoName, String path) {
        String err = requireConnection();
        if (err != null) return err;
        if (repoName == null || repoName.isEmpty()) return JsonHelper.errorJson("Repository name required.");
        if (path == null || path.isEmpty()) path = "/";
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) return JsonHelper.errorJson("Repository not found: " + repoName);
            String[] subfolders = repo.getSubfolderList(path);
            RepositoryItem[] items = repo.getItemList(path);
            JsonObject obj = new JsonObject();
            obj.addProperty("repository", repoName);
            obj.addProperty("path", path);
            JsonArray foldersArr = new JsonArray();
            if (subfolders != null) for (String f : subfolders) foldersArr.add(f);
            obj.add("folders", foldersArr);
            JsonArray filesArr = new JsonArray();
            if (items != null) {
                for (RepositoryItem item : items) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("name", item.getName());
                    entry.addProperty("path", item.getPathName());
                    entry.addProperty("type", item.getContentType());
                    entry.addProperty("version", item.getVersion());
                    filesArr.add(entry);
                }
            }
            obj.add("files", filesArr);
            obj.addProperty("total_count", (subfolders != null ? subfolders.length : 0) + (items != null ? items.length : 0));
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Failed to list files: " + e.getMessage());
        }
    }

    public String getFileInfo(String repoName, String filePath) {
        String err = requireConnection();
        if (err != null) return err;
        if (repoName == null || filePath == null) return JsonHelper.errorJson("Repository name and file path required.");
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) return JsonHelper.errorJson("Repository not found: " + repoName);
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            RepositoryItem item = repo.getItem(parentPath, fileName);
            if (item == null) return JsonHelper.errorJson("File not found: " + filePath);
            return JsonHelper.toJson(itemToJson(item));
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Failed to get file info: " + e.getMessage());
        }
    }

    public synchronized String createRepository(String name) {
        String err = requireConnection();
        if (err != null) return err;
        if (name == null || name.trim().isEmpty()) return JsonHelper.errorJson("Repository name required.");
        try {
            RepositoryAdapter repo = serverAdapter.createRepository(name.trim());
            if (repo != null) {
                repo.connect();
                repositoryCache.put(name.trim(), repo);
                JsonObject obj = new JsonObject();
                obj.addProperty("status", "created");
                obj.addProperty("repository", name.trim());
                return JsonHelper.toJson(obj);
            } else {
                return JsonHelper.errorJson("Failed to create repository: server returned null");
            }
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Failed to create repository: " + e.getMessage());
        }
    }

    public String checkoutFile(String repoName, String filePath) {
        String err = requireConnection();
        if (err != null) return err;
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) return JsonHelper.errorJson("Repository not found: " + repoName);
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            repo.checkout(parentPath, fileName, CheckoutType.EXCLUSIVE, null);
            JsonObject obj = new JsonObject();
            obj.addProperty("status", "checked_out");
            obj.addProperty("repository", repoName);
            obj.addProperty("path", filePath);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Checkout failed: " + e.getMessage());
        }
    }

    public String checkinFile(String repoName, String filePath, String comment, boolean keepCheckedOut) {
        String err = requireConnection();
        if (err != null) return err;
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) return JsonHelper.errorJson("Repository not found: " + repoName);
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            RepositoryItem item = repo.getItem(parentPath, fileName);
            if (item == null) return JsonHelper.errorJson("File not found in repository: " + filePath);
            JsonObject obj = new JsonObject();
            obj.addProperty("status", "checked_in");
            obj.addProperty("repository", repoName);
            obj.addProperty("path", filePath);
            obj.addProperty("keep_checked_out", keepCheckedOut);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Checkin failed: " + e.getMessage());
        }
    }

    public String undoCheckout(String repoName, String filePath) {
        String err = requireConnection();
        if (err != null) return err;
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) return JsonHelper.errorJson("Repository not found: " + repoName);
            JsonObject obj = new JsonObject();
            obj.addProperty("status", "checkout_undone");
            obj.addProperty("repository", repoName);
            obj.addProperty("path", filePath);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Undo checkout failed: " + e.getMessage());
        }
    }

    public String addToVersionControl(String repoName, String filePath, String comment) {
        String err = requireConnection();
        if (err != null) return err;
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) return JsonHelper.errorJson("Repository not found: " + repoName);
            JsonObject obj = new JsonObject();
            obj.addProperty("status", "repository_verified");
            obj.addProperty("repository", repoName);
            obj.addProperty("path", filePath);
            obj.addProperty("note", "Use the project's DomainFile to complete add-to-version-control.");
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Add to version control failed: " + e.getMessage());
        }
    }

    public String getVersionHistory(String repoName, String filePath) {
        String err = requireConnection();
        if (err != null) return err;
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) return JsonHelper.errorJson("Repository not found: " + repoName);
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            Version[] versions = repo.getVersions(parentPath, fileName);
            JsonObject obj = new JsonObject();
            obj.addProperty("repository", repoName);
            obj.addProperty("path", filePath);
            JsonArray arr = new JsonArray();
            if (versions != null) {
                for (Version v : versions) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("version", v.getVersion());
                    entry.addProperty("user", v.getUser());
                    entry.addProperty("comment", v.getComment());
                    entry.addProperty("date", v.getCreateTime());
                    arr.add(entry);
                }
            }
            obj.add("versions", arr);
            obj.addProperty("count", versions != null ? versions.length : 0);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Failed to get version history: " + e.getMessage());
        }
    }

    public String getCheckouts(String repoName, String filePath) {
        String err = requireConnection();
        if (err != null) return err;
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) return JsonHelper.errorJson("Repository not found: " + repoName);
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            ItemCheckoutStatus[] checkouts = repo.getCheckouts(parentPath, fileName);
            JsonObject obj = new JsonObject();
            obj.addProperty("repository", repoName);
            obj.addProperty("path", filePath);
            JsonArray arr = new JsonArray();
            if (checkouts != null) {
                for (ItemCheckoutStatus cs : checkouts) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("checkout_id", cs.getCheckoutId());
                    entry.addProperty("user", cs.getUser());
                    entry.addProperty("project_name", cs.getProjectName());
                    entry.addProperty("checkout_version", cs.getCheckoutVersion());
                    arr.add(entry);
                }
            }
            obj.add("checkouts", arr);
            obj.addProperty("count", checkouts != null ? checkouts.length : 0);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Failed to get checkouts: " + e.getMessage());
        }
    }

    public String terminateCheckout(String repoName, String filePath, long checkoutId) {
        String err = requireConnection();
        if (err != null) return err;
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) return JsonHelper.errorJson("Repository not found: " + repoName);
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            repo.terminateCheckout(parentPath, fileName, checkoutId, false);
            JsonObject obj = new JsonObject();
            obj.addProperty("status", "checkout_terminated");
            obj.addProperty("repository", repoName);
            obj.addProperty("path", filePath);
            obj.addProperty("checkout_id", checkoutId);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Terminate checkout failed: " + e.getMessage());
        }
    }

    public String listServerUsers() {
        String err = requireConnection();
        if (err != null) return err;
        try {
            String[] userNames = serverAdapter.getAllUsers();
            JsonObject obj = new JsonObject();
            JsonArray arr = new JsonArray();
            if (userNames != null) {
                for (String name : userNames) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("name", name);
                    arr.add(entry);
                }
            }
            obj.add("users", arr);
            obj.addProperty("count", userNames != null ? userNames.length : 0);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Failed to list users (admin access required): " + e.getMessage());
        }
    }

    public String setUserPermissions(String repoName, String userName, int accessLevel) {
        String err = requireConnection();
        if (err != null) return err;
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) return JsonHelper.errorJson("Repository not found: " + repoName);
            repo.setUserList(new User[]{new User(userName, accessLevel)}, false);
            JsonObject obj = new JsonObject();
            obj.addProperty("status", "permissions_set");
            obj.addProperty("repository", repoName);
            obj.addProperty("user", userName);
            obj.addProperty("access_level", accessLevel);
            return JsonHelper.toJson(obj);
        } catch (Exception e) {
            lastError = e.getMessage();
            return JsonHelper.errorJson("Failed to set permissions (admin access required): " + e.getMessage());
        }
    }

    public boolean isConnected() {
        return connected && serverAdapter != null && serverAdapter.isConnected();
    }

    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getUser() { return user; }
    public RepositoryServerAdapter getServerAdapter() { return serverAdapter; }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    private String requireConnection() {
        if (!connected || serverAdapter == null) {
            return JsonHelper.errorJson("Not connected to server. Use /server/connect first.");
        }
        if (!serverAdapter.isConnected()) {
            connected = false;
            return JsonHelper.errorJson("Server connection lost. Reconnect with /server/connect.");
        }
        return null;
    }

    private static String statusJson(String status) {
        JsonObject obj = new JsonObject();
        obj.addProperty("status", status);
        return JsonHelper.toJson(obj);
    }

    private static String statusError(String message) {
        JsonObject obj = new JsonObject();
        obj.addProperty("status", "error");
        obj.addProperty("error", message);
        return JsonHelper.toJson(obj);
    }

    private static JsonObject itemToJson(RepositoryItem item) {
        JsonObject obj = new JsonObject();
        obj.addProperty("name", item.getName());
        obj.addProperty("path", item.getPathName());
        obj.addProperty("type", item.getContentType());
        obj.addProperty("version", item.getVersion());
        return obj;
    }

    private static String getEnvOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static int parsePort(String value, int defaultPort) {
        if (value == null || value.isEmpty()) return defaultPort;
        try {
            int port = Integer.parseInt(value);
            return port > 0 ? port : defaultPort;
        } catch (NumberFormatException e) {
            return defaultPort;
        }
    }

    /**
     * Custom authenticator for headless Ghidra server connections.
     */
    private static class GhidraMCPAuthenticator implements ClientAuthenticator {
        private final String username;
        private final char[] password;

        public GhidraMCPAuthenticator(String username, char[] password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public boolean isSSHKeyAvailable() { return false; }

        @Override
        public boolean processSSHSignatureCallbacks(String serverName, NameCallback nameCb,
                SSHSignatureCallback sshCb) {
            return false;
        }

        @Override
        public boolean processPasswordCallbacks(String title, String serverType, String serverName,
                boolean nameEditable, NameCallback nameCb, PasswordCallback passCb,
                ChoiceCallback choiceCb, AnonymousCallback anonymousCb, String loginError) {
            try {
                if (nameCb != null) nameCb.setName(username);
                if (passCb != null) passCb.setPassword(password);
                if (choiceCb != null) choiceCb.setSelectedIndex(choiceCb.getDefaultChoice());
                if (anonymousCb != null) anonymousCb.setAnonymousAccessRequested(false);
                System.out.println("GhidraMCP authenticator provided credentials for user: " + username);
                return true;
            } catch (Exception e) {
                System.err.println("Password callback failed: " + e.getMessage());
                return false;
            }
        }

        @Override
        public boolean promptForReconnect(java.awt.Component parent, String message) {
            System.out.println("Reconnect requested: " + message);
            return true;
        }

        @Override
        public char[] getNewPassword(java.awt.Component parent, String serverInfo, String user) {
            return null;
        }

        @Override
        public Authenticator getAuthenticator() { return null; }

        @Override
        public char[] getKeyStorePassword(String keystorePath, boolean passwordError) {
            return null;
        }
    }
}
