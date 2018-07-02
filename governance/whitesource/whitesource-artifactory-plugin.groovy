/**
 * Copyright (C) 2016 WhiteSource Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import groovy.transform.Field
import org.artifactory.build.*
import org.artifactory.common.*
import org.artifactory.exception.*
import org.artifactory.fs.*
import org.artifactory.fs.ItemInfo
import org.artifactory.repo.*
import org.artifactory.repo.RepoPath
import org.artifactory.repo.RepoPathFactory
import org.artifactory.request.*
import org.artifactory.resource.*
import org.artifactory.util.*
import org.whitesource.agent.FileSystemScanner
import org.whitesource.agent.api.dispatch.CheckPolicyComplianceResult
import org.whitesource.agent.api.dispatch.GetDependencyDataResult
import org.whitesource.agent.api.dispatch.UpdateInventoryResult
import org.whitesource.agent.api.model.*
import org.whitesource.agent.api.model.AgentProjectInfo
import org.whitesource.agent.api.model.PolicyCheckResourceNode
import org.whitesource.agent.api.model.ResourceInfo
import org.whitesource.agent.api.model.VulnerabilityInfo.*
import org.whitesource.agent.api.model.VulnerabilityInfo
import org.whitesource.agent.client.WhitesourceService
import org.whitesource.agent.FileSystemScanner
import org.whitesource.agent.api.model.AgentProjectInfo
import org.whitesource.agent.api.model.DependencyInfo
import org.whitesource.fs.configuration.ConfigurationSerializer
import org.whitesource.fs.configuration.ResolverConfiguration
import org.whitesource.fs.configuration.*
import org.whitesource.fs.FSAConfiguration

import javax.ws.rs.core.*
import javax.ws.rs.core.*
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import java.util.Properties


@Field final String ACTION = 'WSS-Action'
@Field final String POLICY_DETAILS = 'WSS-Policy-Details'
@Field final String DESCRIPTION = 'WSS-Description'
@Field final String HOME_PAGE_URL = 'WSS-Homepage'
@Field final String LICENSES = 'WSS-Licenses'
@Field final String VULNERABILITY = 'WSS-Vulnerability: '
@Field final String VULNERABILITY_SEVERITY = 'WSS-Vulnerability-Severity: '
@Field final String VULNERABILITY_SCORE = 'WSS-Vulnerability-Score: '
@Field final String TEMP_DOWNLOAD_DIRECTORY = System.getProperty('java.io.tmpdir')
@Field final String CVE_URL = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name='
@Field final String INCLUDES_REPOSITORY_CONTENT = 'includesRepositoryContent'

@Field final String PROPERTIES_FILE_PATH = 'plugins/whitesource-artifactory-plugin.properties'
@Field final String AGENT_TYPE = 'artifactory-plugin'
@Field final String PLUGIN_VERSION = '18.5.1'
@Field final String AGENT_VERSION = '2.6.9'
@Field final String OR = '|'
@Field final int MAX_REPO_SIZE = 10000
@Field final int MAX_REPO_SIZE_TO_UPLOAD = 2000

@Field final String BLANK = ''
@Field final String DEFAULT_SERVICE_URL = 'https://saas.whitesourcesoftware.com/agent'
@Field final String REJECT = 'Reject'
@Field final String ACCEPT = 'Accept'
@Field final int DEFAULT_CONNECTION_TIMEOUT_MINUTES = 60

// file system scanner
@Field final boolean CASE_SENSITIVE_GLOB = false
@Field final boolean FOLLOW_SYMLINKS = false
@Field final int ARCHIVE_EXTRACTION_DEPTH = 2
@Field final boolean PARTIAL_SHA1_MATCH = false

@Field final String GLOB_PATTERN_PREFIX = '**/*'
@Field final String PREFIX = '**/*.'
@Field final String BACK_SLASH = '/'

@Field final String REMOTE = 'remote'
@Field final String VIRTUAL = 'virtual'

/**
 * This is a plug-in that integrates Artifactory with WhiteSource
 * Extracts descriptive information from your open source libraries located in the Artifactory repositories
 * and integrates them with WhiteSource.
 *
 * The plugin will check each item details against the organizational policies
 * Check policies suggests information about the action (approve/reject),
 * and policy details as defined by the user in WhiteSource(for example : Approve some license)
 *  1. WSS-Action
 *  2. WSS-Policy-Details
 * Additional data for the item will be populated in your Artifactory property tab :
 * 1. WSS-Description
 * 2. WSS-HomePage
 * 3. WSS-Licenses
 * 4. WSS-Vulnerabilities
 */

download {

    beforeDownloadRequest { request, repoPath ->
        def config = new ConfigSlurper().parse(new File(ctx.artifactoryHome.haAwareEtcDir, PROPERTIES_FILE_PATH).toURL())
        def rpath = repoPath.path
        def rkey = repoPath.repoKey
        //request.httpRequest.request.coyoteRequest.serverNameMB.strValue
        // get the url of the remote repo
        def repositoryConf = repositories.getRepositoryConfiguration(rkey)
        def type = repositoryConf.type
        String sha1 = null
        if (REMOTE.equals(type)) {
            // get remote repo artifact sha1
            sha1 = getRemoteRepoFileSha1(repositoryConf, rpath)
            createProjectAndCheckPolicyForDownload(rpath, sha1, rkey, config)
        } else if (VIRTUAL.equals(type)) {
            // get virtual repo artifact sha1
            log.info("Virtual repo is currently not supported")
        } else {
            // get local repo artifact sha1
            def repository = RepoPathFactory.create(rkey)
            log.info("Local repo is currently not supported")
            List<ItemInfo> items = new ArrayList<>()
            getRelevantItemSha1(repository, rpath.substring(rpath.lastIndexOf(BACK_SLASH) + 1), items)
            sha1 = repositories.getFileInfo(items.get(0).getRepoPath()).getChecksumsInfo().getSha1()
            createProjectAndCheckPolicyForDownload(rpath, sha1, rkey, config)
        }
    }
}

jobs {
    /**
     * How to set cron execution:
     * cron (java.lang.String) - A valid cron expression used to schedule job runs (see: http://www.quartz-scheduler.org/docs/tutorial/TutorialLesson06.html)
     * 1 - Seconds , 2 - Minutes, 3 - Hours, 4 - Day-of-Month , 5- Month, 6 - Day-of-Week, 7 - Year (optional field).
     * Example :
     * "0 42 9 * * ?"  - Build a trigger that will fire daily at 9:42 am
     */
    updateRepoWithWhiteSource(cron: "0 45 23 * * ?") {
        try {
            log.info("Starting job updateRepoData By WhiteSource")
            def config = new ConfigSlurper().parse(new File(ctx.artifactoryHome.haAwareEtcDir, PROPERTIES_FILE_PATH).toURL())
            CheckPolicyComplianceResult checkPoliciesResult = null
            String[] repositories = config.repoKeys as String[]
            Set<String> archiveIncludes = getAllowedFileExtensions(config.archiveIncludes as String[], false)
            Set<String> archiveIncludesWithPrefix = getAllowedFileExtensions(config.archiveIncludes as String[], true)
            String[] includesRepositoryContent = config.getProperty(INCLUDES_REPOSITORY_CONTENT) as String[]
            if (includesRepositoryContent.size() == 0){
                includesRepositoryContent = buildDefaults()
            }
            includesRepositoryContent = addPrefix(includesRepositoryContent)
            for (String repository : repositories) {
                String productName = config.containsKey('productName') ? config.productName : repository
                Map<String, ItemInfo> sha1ToItemMap = new HashMap<String, ItemInfo>()
                List<ItemInfo> list = new ArrayList<>()
                findAllRepoItems(RepoPathFactory.create(repository), sha1ToItemMap, list, archiveIncludes)
                def compressedFilesFolder = compressOneRepositoryArchiveIntoOneZip(list, repository)
                int repoSize = sha1ToItemMap.size()
                int maxRepoScanSize = config.containsKey('maxRepoScanSize') ? config.maxRepoScanSize > 0 ? config.maxRepoScanSize : MAX_REPO_SIZE : MAX_REPO_SIZE
                int maxRepoUploadWssSize = config.containsKey('maxRepoUploadWssSize') ? config.maxRepoUploadWssSize > 0 ? config.maxRepoUploadWssSize : MAX_REPO_SIZE_TO_UPLOAD : MAX_REPO_SIZE_TO_UPLOAD
                if (repoSize > maxRepoScanSize) {
                    log.warn("The max repository size for check policies in WhiteSource is : ${maxRepoScanSize} items, Job Exiting")
                } else if (repoSize == 0) {
                    log.warn("This repository is empty or not exit : ${repository} , Job Exiting")
                } else {
                    // create project and WhiteSource service
                    Collection<AgentProjectInfo> projects = createProjects(sha1ToItemMap, repository, compressedFilesFolder, includesRepositoryContent, archiveIncludesWithPrefix)
                    WhitesourceService service = createWhiteSourceService(config)
                    // update WhiteSource with repositories
                    String userKey = null
                    if (config.containsKey('userKey')) {
                        userKey = config.userKey
                    }
                    if (config.checkPolicies) {
                        checkPoliciesResult = checkPolicies(service, config.apiKey, productName, BLANK, projects, config.forceCheckAllDependencies ,config.forceUpdate, userKey)
                        if (checkPoliciesResult == null) {
                            break
                        }
                    }
                    if (repoSize > maxRepoUploadWssSize) {
                        log.warn("Max repository size inorder to update WhiteSource is : ${maxRepoUploadWssSize}")
                    } else {
                        //updating the WSS service with scanning results
                        UpdateInventoryResult updateResult = null
                        try {
                            if (config.updateWss) {
                                if (config.forceUpdate || !config.checkPolicies) {
                                    log.info("Sending Update to WhiteSource for repository : ${repository}")
                                    updateResult = service.update(config.apiKey, productName, BLANK, projects, userKey)
                                    logResult(updateResult)
                                } else if (checkPoliciesResult != null) {
                                    log.info("Sending Update to WhiteSource for repository : ${repository}")
                                    if (!checkPoliciesResult.hasRejections()) {
                                        updateResult = service.update(config.apiKey, productName, BLANK, projects, userKey)
                                        logResult(updateResult)
                                    }
                                }
                            }
                        } catch (Exception e) {
                            log.error(e.getMessage())
                            break
                        }
                    }
                    try {
                        populateArtifactoryPropertiesTab(projects, config, repository, service, sha1ToItemMap, checkPoliciesResult, productName, userKey)
                    } catch (Exception e) {
                        log.error(e.getMessage())
                        break
                    }
                    deleteTemporaryFolders(compressedFilesFolder)
                    log.info("Job updateRepoWithWhiteSource has Finished")
                }
            }
        } catch (Exception e) {
            log.warn("Error while running the plugin: ", e.getMessage())
        }
    }
}

storage {

    /**
     * Handle after create events.
     *
     * Closure parameters:
     * item (org.artifactory.fs.ItemInfo) - the original item being created.
     */
    afterCreate { item ->
        try {
            if (!item.isFolder()) {
                def config = new ConfigSlurper().parse(new File(ctx.artifactoryHome.haAwareEtcDir, PROPERTIES_FILE_PATH).toURL())
                Map<String, ItemInfo> sha1ToItemMap = new HashMap<String, ItemInfo>()
                sha1ToItemMap.put(repositories.getFileInfo(item.getRepoPath()).getChecksumsInfo().getSha1(), item)
                List<File> fileList = new ArrayList<>()
                String[] includesRepositoryContent = []
                Set<String> allowedFileExtensions = new HashSet<String>()
                def repoKey = item.getRepoKey()
                Collection<AgentProjectInfo> projects = createProjects(sha1ToItemMap, repoKey, fileList, includesRepositoryContent, allowedFileExtensions)
                WhitesourceService whitesourceService = createWhiteSourceService(config)
                String userKey = null
                if (config.containsKey('userKey')) {
                    userKey = config.userKey
                }
                CheckPolicyComplianceResult checkPoliciesResult = checkPolicies(whitesourceService, config.apiKey, repoKey, BLANK, projects, false, false, userKey)
                if (checkPoliciesResult != null) {
                    String productName = config.productName != null ? config.productName : repository
                    populateArtifactoryPropertiesTab(projects, config, repoKey, whitesourceService, sha1ToItemMap, checkPoliciesResult, productName, userKey)
                    log.info("New Item - {$item} was added to the repository")
                }
            }
        } catch (Exception e) {
            log.warn("Error creating WhiteSource Service " + e)
        }
    }
}


/* --- Private Methods --- */

private void deleteTemporaryFolders(List<File> compressedFilesFolder) {
    File fileExtractorTempFolder = new File(TEMP_DOWNLOAD_DIRECTORY + File.separator + "WhiteSource-ArchiveExtractor")
    if (fileExtractorTempFolder.exists()) {
        //the temp folder used by the WSS file agent is present.
        boolean success = deleteNonEmptyDirectory(fileExtractorTempFolder)
    }
    for (int i = 0; i < compressedFilesFolder.size(); i++) {
        File toRemove = compressedFilesFolder.get(i)
        boolean success = deleteNonEmptyDirectory(toRemove)
    }
}

private boolean deleteNonEmptyDirectory(File dir) {
    if (dir.isDirectory()) {
        File[] children = dir.listFiles()
        for (int i = 0; i < children.length; i++) {
            boolean success = deleteNonEmptyDirectory(children[i])
            if (!success) {
                return false
            }
        }
    }
    return dir.delete()
}

private Set<String> getAllowedFileExtensions(String [] allowedFileExtensionsFromConfigFile, boolean withPrefix) {
    Set<String> allowedFileExtensions = new HashSet<String>()
    for (String key: allowedFileExtensionsFromConfigFile) {
        if (withPrefix) {
            key = PREFIX + key
        }
        allowedFileExtensions.add(key)
    }
    if (allowedFileExtensions.size() == 0) {
        //nothing found in config file. use the defaults
        String tempPrefix = PREFIX
        if (!withPrefix) {
            tempPrefix = ""
        }
        allowedFileExtensions.add(tempPrefix + "jar")
        allowedFileExtensions.add(tempPrefix + "war")
        allowedFileExtensions.add(tempPrefix + "ear")
        allowedFileExtensions.add(tempPrefix + "egg")
        allowedFileExtensions.add(tempPrefix + "zip")
        allowedFileExtensions.add(tempPrefix + "whl")
        allowedFileExtensions.add(tempPrefix + "sca")
        allowedFileExtensions.add(tempPrefix + "sda")
        allowedFileExtensions.add(tempPrefix + "gem")
        allowedFileExtensions.add(tempPrefix + "tar.gz")
        allowedFileExtensions.add(tempPrefix + "tar")
        allowedFileExtensions.add(tempPrefix + "tgz")
        allowedFileExtensions.add(tempPrefix + "tar.bz2")
        allowedFileExtensions.add(tempPrefix + "rpm")
        allowedFileExtensions.add(tempPrefix + "rar")
    }
    return allowedFileExtensions
}

private void handleCheckPoliciesResults(Map<String, PolicyCheckResourceNode> projects, Map<String, ItemInfo> sha1ToItemMap){
    for (String key : projects.keySet()) {
        PolicyCheckResourceNode policyCheckResourceNode = projects.get(key)
        Collection<PolicyCheckResourceNode> children = policyCheckResourceNode.getChildren()
        for (PolicyCheckResourceNode child : children) {
            ItemInfo item = sha1ToItemMap.get(child.getResource().getSha1())
            if (item != null && child.getPolicy() != null) {
                def path = item.getRepoPath()
                if (REJECT.equals(child.getPolicy().getActionType()) || ACCEPT.equals(child.getPolicy().getActionType())) {
                    repositories.setProperty(path, ACTION, child.getPolicy().getActionType())
                    repositories.setProperty(path, POLICY_DETAILS, child.getPolicy().getDisplayName())
                }
            }
        }
    }
}

private updateItemsExtraData(GetDependencyDataResult dependencyDataResult, Map<String, ItemInfo> sha1ToItemMap){
    for (ResourceInfo resource : dependencyDataResult.getResources()) {
        ItemInfo item = sha1ToItemMap.get(resource.getSha1())
        if (item != null) {
            RepoPath repoPath = item.getRepoPath()
            if (!BLANK.equals(resource.getDescription())) {
                repositories.setProperty(repoPath, DESCRIPTION, resource.getDescription())
            }
            if (!BLANK.equals(resource.getHomepageUrl())) {
                repositories.setProperty(repoPath, HOME_PAGE_URL, resource.getHomepageUrl())
            }

            Collection<VulnerabilityInfo> vulns = resource.getVulnerabilities()
            for (VulnerabilityInfo vulnerabilityInfo : vulns) {
                String vulnName = vulnerabilityInfo.getName()
                repositories.setProperty(repoPath, VULNERABILITY + vulnName, "${CVE_URL}${vulnName}")
                repositories.setProperty(repoPath, VULNERABILITY_SEVERITY + vulnName, "${vulnerabilityInfo.getSeverity()}")
                if (vulnerabilityInfo.getScore() != null && vulnerabilityInfo.getScore() > 0) {
                    repositories.setProperty(repoPath, VULNERABILITY_SCORE + vulnName, "${vulnerabilityInfo.getScore()}")
                }
            }
            Collection<String> licenses = resource.getLicenses()
            String dataLicenses = BLANK
            for (String license : licenses) {
                dataLicenses += license + ", "
            }
            if (dataLicenses.size() > 0) {
                dataLicenses = dataLicenses.substring(0, dataLicenses.size() - 2)
                repositories.setProperty(repoPath, LICENSES, dataLicenses)
            }
        }
    }
}

private void findAllRepoItems(
        def repoPath, Map<String, ItemInfo> sha1ToItemMap, List<ItemInfo> list, Set<String> allowedFileExtensions = null) {
    if (allowedFileExtensions == null || allowedFileExtensions.size() == 0 ) {
        log.error("No file extensions list was provided.")
        return
    }
    for (ItemInfo item : repositories.getChildren(repoPath)) {
        if (item.isFolder()) {
            findAllRepoItems(item.getRepoPath(), sha1ToItemMap, list, allowedFileExtensions)
        } else {
            String endsWith = item.getName()
            int index = endsWith.lastIndexOf(".")
            sha1ToItemMap.put(repositories.getFileInfo(item.getRepoPath()).getChecksumsInfo().getSha1(), item)
            if ( item.getName().lastIndexOf(".") > -1) {
                endsWith = endsWith.substring(index + 1)
                if (allowedFileExtensions.contains(endsWith)) {
                    list.add(item.getRepoPath())
                } else {
                    log.info("The following item will not be checked, as its extension is not defined in config file: " + item.getName())
                }
            }
        }
    }
    return
}

private void populateArtifactoryPropertiesTab(Collection<AgentProjectInfo> projects, def config, String repoName,
                                              WhitesourceService whitesourceService, Map<String, ItemInfo> sha1ToItemMap,
                                              CheckPolicyComplianceResult checkPoliciesResult, String productName, String userKey) {
    // get policies and dependency data result and update properties tab for each artifact
    try {
        int repoSize = sha1ToItemMap.size()
        log.info("Finished updating WhiteSource with ${repoSize} artifacts")
        GetDependencyDataResult dependencyDataResult = whitesourceService.getDependencyData(config.apiKey, productName, BLANK, projects, userKey)
        log.info("Updating additional dependency data")
        updateItemsExtraData(dependencyDataResult, sha1ToItemMap)
        log.info("Finished updating additional dependency data")
        if (config.checkPolicies && checkPoliciesResult != null) {
            log.info("Updating policies for repository: ${repoName}")
            handleCheckPoliciesResults(checkPoliciesResult.getNewProjects(), sha1ToItemMap)
            handleCheckPoliciesResults(checkPoliciesResult.getExistingProjects(), sha1ToItemMap)
            log.info("Finished updating policies for repository : ${repoName}")
        }
    } catch (Exception e) {
        log.warn("Error Updating property tab " + e)
    }
}

private Collection<AgentProjectInfo> createProjects(Map<String, ItemInfo> sha1ToItemMap, String repoName, List<File> compressedFilesFolder,
                                                    String[] includesRepositoryContent, Set<String> allowedFileExtensions) {
    Collection<AgentProjectInfo> projects = new ArrayList<AgentProjectInfo>()
    AgentProjectInfo projectInfo = new AgentProjectInfo()
    projects.add(projectInfo)
    projectInfo.setCoordinates(new Coordinates(null, repoName, BLANK))
    List<DependencyInfo> dependencies = new ArrayList<DependencyInfo>()
    for (String key : sha1ToItemMap.keySet()) {
        DependencyInfo dependencyInfo = new DependencyInfo(key)
        String archiveName = sha1ToItemMap.get(key).getName()
        dependencyInfo.setArtifactId(archiveName)
        dependencies.add(dependencyInfo)
        String compressedFilesFolderName = null
        File compressedFile
        ResolverConfiguration resolverConfiguration = fsaConfiguration.getResolver()
        // set resolvers to false
        resolverConfiguration.setBowerResolveDependencies(false)
        resolverConfiguration.setGradleResolveDependencies(false)
        resolverConfiguration.setMavenResolveDependencies(false)
        resolverConfiguration.setNpmResolveDependencies(false)
        resolverConfiguration.setNugetResolveDependencies(false)
        resolverConfiguration.setPythonResolveDependencies(false)
        for (int i = 0; i < compressedFilesFolder.size(); i++) {
            compressedFile = compressedFilesFolder.get(i)
            if (compressedFile.getPath().toString().endsWith(archiveName)) {
                compressedFilesFolderName = compressedFile.getPath()
                String currentArchiveFileNameWithPrefix = GLOB_PATTERN_PREFIX + sha1ToItemMap.get(key).getName()
                String [] exclude = [sha1ToItemMap.get(key).getName()]//'' //[currentArchiveFileNameWithPrefix]
                java.util.Properties properties= new Properties()
                properties.put('includes', includesRepositoryContent)
                properties.put('excludes', exclude)
                FSAConfiguration fsaConfiguration = new FSAConfiguration(properties)
                Map<String, Set<String>> appPathsToDependencyDirs = new HashMap<>()
                List<DependencyInfo> dependencyInfos = new FileSystemScanner(resolverConfiguration, fsaConfiguration.getAgent(), false).createProjects(
                        Arrays.asList(compressedFilesFolderName), appPathsToDependencyDirs, false, includesRepositoryContent, exclude, CASE_SENSITIVE_GLOB,
                        ARCHIVE_EXTRACTION_DEPTH, allowedFileExtensions.toArray(new String[allowedFileExtensions.size()]), new String[0],
                        false, FOLLOW_SYMLINKS, new ArrayList<>(), PARTIAL_SHA1_MATCH)
                dependencyInfo.getChildren().addAll(dependencyInfos)
                break
            }
        }
    }
    projectInfo.setDependencies(dependencies)
    return projects
}

private CheckPolicyComplianceResult checkPolicies(WhitesourceService service, String orgToken, String product, String productVersion,
                                                  Collection<AgentProjectInfo> projects, boolean forceCheckAllDependencies, boolean  forceUpdate, String userKey) {
    log.info("Checking policies")
    CheckPolicyComplianceResult checkPoliciesResult = null
    try {
        checkPoliciesResult = service.checkPolicyCompliance(orgToken, product, productVersion, projects, forceCheckAllDependencies, userKey)
    } catch (Exception e) {
        log.error(e.getMessage())
        return null
    }
    if (checkPoliciesResult != null) {
        boolean hasRejections = checkPoliciesResult.hasRejections()
        if (hasRejections && !forceUpdate) {
            log.info("Some dependencies did not conform with open source policies")
            log.info("=== UPDATE ABORTED ===")
        } else {
            String message = hasRejections ? "Some dependencies violate open source policies, however all were force " +
                    "updated to organization inventory." :
                    "All dependencies conform with open source policies."
            log.info(message)
        }
    }
    return checkPoliciesResult
}

private WhitesourceService createWhiteSourceService(def config) {
    String url = BLANK.equals(config.wssUrl) ? DEFAULT_SERVICE_URL : config.wssUrl
    boolean setProxy = false
    if (config.useProxy) {
        setProxy = true
    }
    try {
        // create whiteSource service and check proxy settings
        // default value for certificate check is false
        WhitesourceService service = new WhitesourceService(AGENT_TYPE, AGENT_VERSION, PLUGIN_VERSION, url, setProxy, DEFAULT_CONNECTION_TIMEOUT_MINUTES, false)
        if (setProxy) {
            checkAndSetProxySettings(service, config)
        }
        return service
    } catch (Exception e) {
        log.warn("Error creating WhiteSource Service " + e.getLocalizedMessage())
        return null
    }
}

private void checkAndSetProxySettings(WhitesourceService whitesourceService, def config) {
    if (config.useProxy) {
        log.info("Setting proxy settings")
        def proxyPort = config.proxyPort
        final String proxyHost = config.proxyHost
        final String proxyUser = null
        final String proxyPass = null
        if (!BLANK.equals(config.proxyUser) && !BLANK.equals(config.proxyPass)) {
            proxyUser = config.proxyUser
            proxyPass = config.proxyPass
        }
        whitesourceService.getClient().setProxy(proxyHost, proxyPort, proxyUser, proxyPass)
    }
}

private void logResult(UpdateInventoryResult updateResult) {
    StringBuilder resultLogMsg = new StringBuilder("Inventory update results for ").append(updateResult.getOrganization()).append("\n")
    // newly created projects
    Collection<String> createdProjects = updateResult.getCreatedProjects()
    if (createdProjects.isEmpty()) {
        resultLogMsg.append("No new projects found.").append("\n")
    } else {
        resultLogMsg.append("Newly created projects:").append("\n")
        for (String projectName : createdProjects) {
            resultLogMsg.append(projectName).append("\n")
        }
    }
    // updated projects
    Collection<String> updatedProjects = updateResult.getUpdatedProjects()
    if (updatedProjects.isEmpty()) {
        resultLogMsg.append("No projects were updated.").append("\n")
    } else {
        resultLogMsg.append("Updated projects:").append("\n")
        for (String projectName : updatedProjects) {
            resultLogMsg.append(projectName).append("\n")
        }
    }
    log.info(resultLogMsg.toString())
}

private List<File> compressOneRepositoryArchiveIntoOneZip(List list, String repository) throws IOException {
    byte[] data = new byte[2048]
    List<File> listOfArchiveFiles = new ArrayList<>()
    File archiveFile = null
    FileOutputStream fileOutputStream
    ZipOutputStream zipOutputStream
    for (int i =0; i < list.size() ; i++) {
        def artifactName = list.get(i).getPath().substring(list.get(i).getPath().lastIndexOf(BACK_SLASH) + 1)
        File destDir = new File(TEMP_DOWNLOAD_DIRECTORY + File.separator + repository + System.nanoTime() + File.separator + artifactName)//+ list.get(i).getPath())
        if (!destDir.exists()) {
            destDir.mkdirs()
        }
        archiveFile = new File(destDir.getPath() + File.separator + artifactName)  //list.get(i).getPath())
        fileOutputStream = new FileOutputStream(archiveFile)
        zipOutputStream = new ZipOutputStream(fileOutputStream)
        ZipEntry ze = new ZipEntry(list.get(i).getPath())
        zipOutputStream.putNextEntry(ze)
        InputStream inputStream
        try {
            inputStream = repositories.getContent(list.get(i)).getInputStream()
            int len
            while ((len = inputStream.read(data)) > 0) {
                zipOutputStream.write(data, 0, len)
            }
        } finally {
            inputStream.close()
            zipOutputStream.closeEntry()
            zipOutputStream.close()
            fileOutputStream.close()
        }
        listOfArchiveFiles.add(destDir)
    }
    return listOfArchiveFiles
}

private String [] buildDefaults(){
    String [] defaultArray = [
            "as", "asp", "aspx", "c", "h", "s", "cc", "cp", "cpp", "cxx", "c++", "hpp", "hxx", "h++", "hh", "mm", "c#", "cs",
            "csharp", "go", "goc", "html", "m", "pch", "java", "js", "jsp", "pl", "plx", "pm", "ph", "cgi", "fcgi", "psgi",
            "al", "perl", "t", "p6m", "p6l", "nqp", "6pl", "6pm", "p6", "php", "py", "rb", "swift", "clj", "cljc", "cljs",
            "cljx", "y", "jar", "war", "aar", "ear", "dll", "exe", "msi", "gem", "egg", "tar.gz", "whl", "rpm", "deb", "drpm",
            "dmg", "udeb", "so", "ko", "a", "ar", "nupkg", "air", "apk", "swc", "swf", "bz2", "gzip", "tar.bz2", "tgz", "zip"]
    return defaultArray
}

private String[] addPrefix(String[] values){
    String[] updated = new String [values.size()]
    for (int i=0; i<values.size(); i++){
        updated[i] = PREFIX + values[i]
    }
    return updated
}

private void createProjectAndCheckPolicyForDownload(def rpath, def sha1, def rkey, def config) {
    def artifactName = rpath.substring(rpath.lastIndexOf(BACK_SLASH) + 1)
    String productName = config.productName != null ? config.productName : rkey
    Collection<AgentProjectInfo> projects = createProjectWithOneDependency(sha1, artifactName, rkey)
    WhitesourceService whitesourceService = createWhiteSourceService(config)
    String userKey = null
    if (config.containsKey('userKey')) {
        userKey = config.userKey
    }
    CheckPolicyComplianceResult checkPoliciesResult
    try {
        checkPoliciesResult = checkPolicies(whitesourceService, config.apiKey, rkey, BLANK, projects, false, false, userKey)
    } catch (Exception e) {
        log.error(e.getMessage())
    }
    def name = ''
    if (checkPoliciesResult != null) {
        if (checkPoliciesResult.hasRejections() == true) {
            def project = checkPoliciesResult.getNewProjects()
            for (String key : project.keySet()) {
                PolicyCheckResourceNode policyCheckResourceNode = project.get(key)
                Collection<PolicyCheckResourceNode> children = policyCheckResourceNode.getChildren()
                for (PolicyCheckResourceNode child : children) {
                    name = child.getPolicy().getDisplayName()
                }
            }
            def status = 403
            def message = "${artifactName} did not conform with open source policies :  ${name}"
            log.warn message
            throw new CancelException(message, status) {
                public Throwable fillInStackTrace() {
                    return null
                }

            }
        } else {
            def message = "All the epolicies comform with  :  ${artifactName}"
            log.info message
        }
    }
}

private Collection<AgentProjectInfo> createProjectWithOneDependency(String sha1, String fileName, String repoName) {
    Collection<AgentProjectInfo> projects = new ArrayList<AgentProjectInfo>()
    AgentProjectInfo projectInfo = new AgentProjectInfo()
    projects.add(projectInfo)
    projectInfo.setCoordinates(new Coordinates(null, repoName, BLANK))
    List<DependencyInfo> dependencies = new ArrayList<DependencyInfo>()
    DependencyInfo dependencyInfo = new DependencyInfo(sha1)
    dependencyInfo.setArtifactId(fileName)
    dependencies.add(dependencyInfo)
    projectInfo.setDependencies(dependencies)
    return projects
}

private String getRemoteRepoFileSha1(def conf, def rpath){
    def url =conf.url
    if (!url.endsWith('/')) url += '/'
    url += rpath
    // get the remote authorization data
    def auth = "$conf.username:$conf.password".bytes.encodeBase64()
    def conn = null, istream = null, realchecksum = null
    try {
        // open a connection to the remote
        conn = new URL(url).openConnection()
        conn.setRequestMethod('HEAD')
        conn.setRequestProperty('Authorization', "Basic $auth")
        // don't modify the path if this file already exists on the far end
    } finally {
        // close everything
        istream?.close()
        conn?.disconnect()
    }
    // operation, attempt to pull the checksum from the far end
    // get the url of the remote repo
    url = conf.url
    if (!url.endsWith('/')) url += '/'
    url += rpath
    // get the remote authorization data
    conn = null
    istream = null
    try {
        // open a connection to the remote
        conn = new URL(url).openConnection()
        conn.setRequestProperty('Authorization', "Basic $auth")
        // don't modify the path if the source file does not exist
        def response = conn.responseCode
        if (response < 200 || response >= 300) return
        // calculate the checksum of the response data
        istream = conn.inputStream
        def digest = MessageDigest.getInstance('SHA1')
        def buf = new byte[4096]
        def len = istream.read(buf)
        while (len != -1) {
            digest.update(buf, 0, len)
            len = istream.read(buf)
        }
        realchecksum = digest.digest().encodeHex().toString()
    } finally {
        // close everything
        istream?.close()
        conn?.disconnect()
    }
    return realchecksum
}

private void getRelevantItemSha1(def repository, def fileName, List<ItemInfo> items) {
    for (ItemInfo item : repositories.getChildren(repository)) {
        if (item.isFolder()) {
            getRelevantItemSha1(item.getRepoPath(), fileName, items)
        } else {
            if (fileName.equals(item.getName())) {
                items.add(item)
                break
            }
        }
    }
    return
}
