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
import org.artifactory.repo.*
import org.artifactory.request.*
import org.artifactory.resource.*
import org.artifactory.util.*
import org.whitesource.agent.FileSystemScanner
import org.whitesource.agent.api.dispatch.GetDependencyDataResult
import org.whitesource.agent.api.model.*
import org.whitesource.agent.client.WhitesourceService
import org.whitesource.agent.api.dispatch.CheckPolicyComplianceResult
import org.whitesource.agent.api.dispatch.UpdateInventoryResult
import org.whitesource.agent.api.model.AgentProjectInfo

import javax.ws.rs.core.*
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@Field final String ACTION = 'WSS-Action'
@Field final String POLICY_DETAILS = 'WSS-Policy-Details'
@Field final String DESCRIPTION = 'WSS-Description'
@Field final String HOME_PAGE_URL = 'WSS-Homepage'
@Field final String LICENSES = 'WSS-Licenses'
@Field final String VULNERABILITY = 'WSS-Vulnerability: '
@Field final String VULNERABILITY_SEVERITY = 'WSS-Vulnerability-Severity: '
@Field final String TEMP_DOWNLOAD_DIRECTORY = System.getProperty('java.io.tmpdir')
@Field final String CVE_URL = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name='
@Field final String INCLUDES_REPOSITORY_CONTENT = 'includesRepositoryContent'

@Field final String PROPERTIES_FILE_PATH = 'plugins/whitesource-artifactory-plugin.properties'
@Field final String AGENT_TYPE = 'artifactory-plugin'
@Field final String PLUGIN_VERSION = '1.0.4'
@Field final String AGENT_VERSION = '2.2.7'
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

jobs {
    /**
     * How to set cron execution:
     * cron (java.lang.String) - A valid cron expression used to schedule job runs (see: http://www.quartz-scheduler.org/docs/tutorial/TutorialLesson06.html)
     * 1 - Seconds , 2 - Minutes, 3 - Hours, 4 - Day-of-Month , 5- Month, 6 - Day-of-Week, 7 - Year (optional field).
     * Examples :
     * "0 42 9 * * ?"  - Build a trigger that will fire daily at 9:42 am
     * "0 0/2 8-17 * * ?" - Build a trigger that will fire every other minute, between 8am and 5pm, every day
     */
    updateRepoWithWhiteSource(cron: "0 07 18 * * ?") {
        try {
            log.info("Starting job updateRepoData By WhiteSource")
            def config = new ConfigSlurper().parse(new File(ctx.artifactoryHome.haAwareEtcDir, PROPERTIES_FILE_PATH).toURL())
            CheckPolicyComplianceResult checkPoliciesResult
            String[] repositories = config.repoKeys as String[]
            Set<String> archiveIncludes = getAllowedFileExtensions(config.archiveIncludes as String[], false)
            Set<String> archiveIncludesWithPrefix = getAllowedFileExtensions(config.archiveIncludes as String[], true)
            String[] includesRepositoryContent = config.getProperty(INCLUDES_REPOSITORY_CONTENT) as String[]
            if (includesRepositoryContent.size() == 0){
                includesRepositoryContent = buildDefaults()
            }
            includesRepositoryContent = addPrefix(includesRepositoryContent)
            for (String repository : repositories) {
                Map<String, ItemInfo> sha1ToItemMap = new HashMap<String, ItemInfo>()
                List<ItemInfo> list = new ArrayList<>()
                findAllRepoItems(RepoPathFactory.create(repository), sha1ToItemMap, list, archiveIncludes)
                def compressedFilesFolder = compressOneRepositoryArchiveIntoOneZip(list, repository)
                int repoSize = sha1ToItemMap.size()
                if (repoSize > MAX_REPO_SIZE) {
                    log.warn("The max repository size for check policies in WhiteSource is : ${repoPath} items, Job Exiting")
                } else if (repoSize == 0) {
                    log.warn("This repository is empty or not exit : ${repository} , Job Exiting")
                } else {
                    // create project and WhiteSource service
                    Collection<AgentProjectInfo> projects = createProjects(sha1ToItemMap, repository, compressedFilesFolder, includesRepositoryContent, archiveIncludesWithPrefix)
                    WhitesourceService service = createWhiteSourceService(config)
                    // update WhiteSource with repositories with no more than 2000 artifacts
                    log.info("Sending Update to WhiteSource for repository : ${repository}")
                    if (repoSize > MAX_REPO_SIZE_TO_UPLOAD) {
                        log.warn("Max repository size inorder to update WhiteSource is : ${repoPath}")
                    } else {
                        //updating the WSS service with scanning results
                        if (config.checkPolicies) {
                            checkPoliciesResult = checkPolicies(service, config.apiKey, config.productName, BLANK, projects, config.forceCheckAllDependencies ,config.forceUpdate)
                        }
                        if ((checkPoliciesResult.hasRejections() != null || !checkPoliciesResult.hasRejections()) || config.forceUpdate) {
                            UpdateInventoryResult updateResult = service.update(config.apiKey, config.productName, BLANK, projects);
                            logResult(updateResult)
                        }
                    }
                    populateArtifactoryPropertiesTab(projects, config, repository, service, sha1ToItemMap, checkPoliciesResult)
                    deleteTemporaryFolders(compressedFilesFolder)
                }
            }
        } catch (Exception e) {
            log.warn("Error while running the plugin: {}", e.getMessage())
        }
        log.info("Job updateRepoWithWhiteSource has Finished")
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
                Collection<AgentProjectInfo> projects = createProjects(sha1ToItemMap, item.getRepoKey() , fileList, includesRepositoryContent, allowedFileExtensions)
                WhitesourceService whitesourceService = createWhiteSourceService(config)
                CheckPolicyComplianceResult checkPoliciesResult = checkPolicies(whitesourceService, config.apiKey,
                        item.getRepoKey(), BLANK, projects, false ,false)
                populateArtifactoryPropertiesTab(projects, config, item.getRepoKey(), whitesourceService, sha1ToItemMap, checkPoliciesResult)
            }
        } catch (Exception e) {
            log.warn("Error while running the plugin: {$e.getMessage()}")
        }
        log.info("New Item - {$item} was added to the repository")
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
                                              WhitesourceService whitesourceService, Map<String, ItemInfo> sha1ToItemMap, CheckPolicyComplianceResult checkPoliciesResult) {
    // get policies and dependency data result and update properties tab for each artifact
    try {
        int repoSize = sha1ToItemMap.size()
        log.info("Finished updating WhiteSource with ${repoSize} artifacts")
        GetDependencyDataResult dependencyDataResult = whitesourceService.getDependencyData(config.apiKey, config.productName, BLANK, projects)
        log.info("Updating additional dependency data")
        updateItemsExtraData(dependencyDataResult, sha1ToItemMap)
        log.info("Finished updating additional dependency data")
        if (config.checkPolicies) {
            log.info("Updating policies for repository: ${repoName}")
            handleCheckPoliciesResults(checkPoliciesResult.getNewProjects(), sha1ToItemMap)
            handleCheckPoliciesResults(checkPoliciesResult.getExistingProjects(), sha1ToItemMap)
            log.info("Finished updating policies for repository : ${repoName}")
        }
    } catch (Exception e) {
        log.warn("Error while running the plugin: ${e.getMessage()}")
    }
}

private Collection<AgentProjectInfo> createProjects(Map<String, ItemInfo> sha1ToItemMap, String repoName, List<File> compressedFilesFolder, String[] includesRepositoryContent, Set<String> allowedFileExtensions) {
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
        File oneFile
        for (int i = 0; i < compressedFilesFolder.size(); i++) {
            oneFile = compressedFilesFolder.get(i)
            if (oneFile.getPath().toString().endsWith(archiveName)) {
                compressedFilesFolderName = oneFile.getPath()
                String currentArchiveFileNameWithPrefix = GLOB_PATTERN_PREFIX + sha1ToItemMap.get(key).getName()
                String [] exclude = [currentArchiveFileNameWithPrefix]
                List<DependencyInfo> dependencyInfos = new FileSystemScanner(false, null).createDependencies(
                        Arrays.asList(compressedFilesFolderName), null, includesRepositoryContent , exclude, CASE_SENSITIVE_GLOB,
                        ARCHIVE_EXTRACTION_DEPTH, allowedFileExtensions.toArray(new String[allowedFileExtensions.size()]), new String[0], FOLLOW_SYMLINKS, new ArrayList<String>(), PARTIAL_SHA1_MATCH)
                dependencyInfo.getChildren().addAll(dependencyInfos)
                break
            }
        }
    }
    projectInfo.setDependencies(dependencies)
    return projects
}

private CheckPolicyComplianceResult checkPolicies(WhitesourceService service, String orgToken, String product, String productVersion,
                                                  Collection<AgentProjectInfo> projects, boolean forceCheckAllDependencies, boolean  forceUpdate ) {
    log.info("Checking policies")
    CheckPolicyComplianceResult checkPoliciesResult = service.checkPolicyCompliance(orgToken, product, productVersion, projects, forceCheckAllDependencies)
    boolean hasRejections = checkPoliciesResult.hasRejections()
    if (hasRejections && !forceUpdate) {
        log.info("Some dependencies did not conform with open source policies, review report for details")
        log.info("=== UPDATE ABORTED ===")
    } else {
        String message = hasRejections ? "Some dependencies violate open source policies, however all were force " +
                "updated to organization inventory." :
                "All dependencies conform with open source policies."
        log.info(message)
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
        WhitesourceService service = new WhitesourceService(AGENT_TYPE, AGENT_VERSION, PLUGIN_VERSION,url, setProxy, DEFAULT_CONNECTION_TIMEOUT_MINUTES)
        if (setProxy) {
            checkAndSetProxySettings(service, config)
        }
        return service
    } catch (Exception e) {
        log.warn("Error creating WhiteSource Service: {$e.getMessage()}")
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
        File destDir = new File(TEMP_DOWNLOAD_DIRECTORY + File.separator + repository + '_' + System.nanoTime() + "_" + list.get(i).getPath())
        if (!destDir.exists()) {
            destDir.mkdirs()
        }
        archiveFile = new File(destDir.getPath() + File.separator +  list.get(i).getPath())
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
            "as",
            "asp",
            "aspx",
            "c",
            "h",
            "s",
            "cc",
            "cp",
            "cpp",
            "cxx",
            "c++",
            "hpp",
            "hxx",
            "h++",
            "hh",
            "mm",
            "c#",
            "cs",
            "csharp",
            "go",
            "goc",
            "html",
            "m",
            "pch",
            "java",
            "js",
            "jsp",
            "pl",
            "plx",
            "pm",
            "ph",
            "cgi",
            "fcgi",
            "psgi",
            "al",
            "perl",
            "t",
            "p6m",
            "p6l",
            "nqp",
            "6pl",
            "6pm",
            "p6",
            "php",
            "py",
            "rb",
            "swift",
            "clj",
            "cljc",
            "cljs",
            "cljx",
            "y",
            "jar",
            "war",
            "aar",
            "ear",
            "dll",
            "exe",
            "msi",
            "gem",
            "egg",
            "tar.gz",
            "whl",
            "rpm",
            "deb",
            "drpm",
            "dmg",
            "udeb",
            "so",
            "ko",
            "a",
            "ar",
            "nupkg",
            "air",
            "apk",
            "swc",
            "swf",
            "bz2",
            "gzip",
            "tar.bz2",
            "tgz",
            "zip"
    ]
    return defaultArray
}

private String[] addPrefix(String[] values){
    String[] updated = new String [values.size()]
    for (int i=0; i<values.size(); i++){
        updated[i] = PREFIX + values[i]
    }
    return updated
}
