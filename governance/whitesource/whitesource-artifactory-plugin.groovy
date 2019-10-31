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
import org.artifactory.exception.CancelException
import org.artifactory.fs.*
import org.artifactory.fs.ItemInfo
import org.artifactory.repo.*
import org.artifactory.repo.RepoPath
import org.artifactory.repo.RepoPathFactory
import org.artifactory.request.*
import org.artifactory.resource.*
import org.artifactory.util.*
import org.whitesource.agent.api.dispatch.CheckPolicyComplianceRequest
import org.whitesource.agent.api.dispatch.CheckPolicyComplianceResult
import org.whitesource.agent.api.dispatch.GetDependencyDataResult
import org.whitesource.agent.api.dispatch.UpdateInventoryRequest
import org.whitesource.agent.api.dispatch.UpdateInventoryResult
import org.whitesource.agent.api.model.*
import org.whitesource.agent.client.WhitesourceService

import org.whitesource.agent.api.dispatch.GetDependencyDataRequest
import org.whitesource.utils.archive.ArchiveExtractor
import org.whitesource.agent.hash.ChecksumUtils

import java.security.MessageDigest
import static groovy.io.FileType.FILES

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
@Field final String PLUGIN_VERSION = '19.9.1'
@Field final String AGENT_VERSION = '2.9.9.17'
@Field final String ARCHIVE_EXTRACTION_DEPTH = 'archiveExtractionDepth'
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
@Field final int ARCHIVE_EXTRACTION_DEPTH_DEFAULT = 2
@Field final int ARCHIVE_EXTRACTION_DEPTH_MIN = 1
@Field final int ARCHIVE_EXTRACTION_DEPTH_MAX = 7
@Field final boolean PARTIAL_SHA1_MATCH = false
@Field final String GLOB_PATTERN_PREFIX = '**/*'
@Field final String PREFIX = '**/*.'
@Field final String BACK_SLASH = '/'

@Field final String REMOTE = 'remote'
@Field final String VIRTUAL = 'virtual'

@Field final String[] ARCHIVE_INCLUDES_DEFAULT = ["jar", "war", "ear", "egg", "zip", "whl", "sca", "sda", "gem",
                                                  "tar.gz", "tar", "tgz", "tar.bz2", "rpm", "rar"]

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
        def triggerBeforeDownload = true
        def archiveExtractionDepth = config.containsKey(ARCHIVE_EXTRACTION_DEPTH) ? config.get(ARCHIVE_EXTRACTION_DEPTH) : ARCHIVE_EXTRACTION_DEPTH_DEFAULT
        if (config.containsKey('triggerBeforeDownload')) {
            triggerBeforeDownload = config.triggerBeforeDownload
        }
        if (triggerBeforeDownload) {
            def rpath = repoPath.path
            def rkey = repoPath.repoKey
            // get the url of the remote repo
            def repositoryConf = repositories.getRepositoryConfiguration(rkey)
            def type = repositoryConf.type
            String sha1
            try {
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
                    List<ItemInfo> items = new ArrayList<>()
                    getRelevantItemSha1(repository, rpath.substring(rpath.lastIndexOf(BACK_SLASH) + 1), items)
                    if (!items.isEmpty()) {
                        sha1 = repositories.getFileInfo(items.get(0).getRepoPath()).getChecksumsInfo().getSha1()
                        createProjectAndCheckPolicyForDownload(rpath, sha1, rkey, config)
                    }
                }
            } catch (Exception e) {
                log.warn("Failed to get dependency" + e)
            }
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
    updateRepoWithWhiteSource(cron: "0 28 13 * * ?") {
        try {
            log.info("Starting job updateRepoWithWhiteSource By WhiteSource")

            // Get config properties from 'plugins/whitesource-artifactory-plugin.properties'
            def config = new ConfigSlurper().parse(new File(ctx.artifactoryHome.haAwareEtcDir, PROPERTIES_FILE_PATH).toURL())
            CheckPolicyComplianceResult checkPoliciesResult = null

            // Get artifactory repositories names to scan from config file
            if (config.repoKeys.isEmpty()) {
              List<String> repositories = repositories.getLocalRepositories()
            } else {
              String[] repositories = config.repoKeys as String[]
            }
            // Get archive files extraction depth, Archive extraction depth should be between 1 and 7
            // Default archive extraction depth is 2
            def archiveExtractionDepth = config.containsKey(ARCHIVE_EXTRACTION_DEPTH) ?
                    config.get(ARCHIVE_EXTRACTION_DEPTH) : ARCHIVE_EXTRACTION_DEPTH_DEFAULT
            archiveExtractionDepth = verifyArchiveExtractionDepth(archiveExtractionDepth)

            // Get archive includes extensions from config file
            // or use the default archive extensions 'ARCHIVE_INCLUDES_DEFAULT'
            Set<String> archiveIncludes = getArchiveIncludes(config.archiveIncludes as String[], false)
            Set<String> archiveIncludesWithPrefix = getArchiveIncludes(config.archiveIncludes as String[], true)

            // Get includes extensions you want to scan from config file
            String[] includesRepositoryContent = config.getProperty(INCLUDES_REPOSITORY_CONTENT) as String[]
            if (includesRepositoryContent.size() == 0) {
                includesRepositoryContent = buildDefaults()
            }
            includesRepositoryContent = addPrefix(includesRepositoryContent)

            // Loop over repositories names provided in config
            for (String repository : repositories) {
                List<ItemInfo> archiveFilesList = new ArrayList<>()
                Map<String, WssItemInfo> sha1ToItemMap = new HashMap<String, WssItemInfo>()
                String productName = config.containsKey('productName') ? config.productName : repository

                // Get all repository files/content, fill them in sha1ToItemMap.
                // If file is archive then it will be added to archiveFilesList to extract it later
                findAllRepositoryItems(RepoPathFactory.create(repository), sha1ToItemMap, archiveFilesList, archiveIncludes)

                def archiveFilesDirectories = cloneArchiveFilesToTempDirectory(archiveFilesList, repository)
                archiveFilesList.clear() // clear list - it's not used after this step

                int repoSize = sha1ToItemMap.size()
                int maxRepoScanSize = config.containsKey('maxRepoScanSize') ? config.maxRepoScanSize > 0 ? config.maxRepoScanSize : MAX_REPO_SIZE : MAX_REPO_SIZE
                int maxRepoUploadWssSize = config.containsKey('maxRepoUploadWssSize') ? config.maxRepoUploadWssSize > 0 ? config.maxRepoUploadWssSize : MAX_REPO_SIZE_TO_UPLOAD : MAX_REPO_SIZE_TO_UPLOAD
                if (repoSize > maxRepoScanSize) {
                    log.warn("The max repository size for check policies in WhiteSource is : ${maxRepoScanSize} items, Job Exiting")
                } else if (repoSize == 0) {
                    log.warn("This repository is empty or not exit : ${repository} , Job Exiting")
                } else {
                    // create project and WhiteSource service
                    Collection<AgentProjectInfo> projects = createProjects(sha1ToItemMap, repository, archiveFilesDirectories, includesRepositoryContent,
                            archiveIncludesWithPrefix, archiveExtractionDepth)
                    WhitesourceService service = createWhiteSourceService(config)

                    // update WhiteSource with repositories
                    String userKey = null
                    if (config.containsKey('userKey')) {
                        userKey = config.userKey
                    }

                    if (config.checkPolicies) {
                        checkPoliciesResult = checkPolicies(service, config.apiKey, productName, BLANK, projects, config.forceCheckAllDependencies, config.forceUpdate, userKey)
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
                            UpdateInventoryRequest updateInventoryRequest = new UpdateInventoryRequest(config.apiKey, projects)
                            updateInventoryRequest.setUserKey(userKey)
                            updateInventoryRequest.setProduct(productName)
                            if (config.updateWss) {
                                if (config.forceUpdate || !config.checkPolicies) {
                                    log.info("Sending Update to WhiteSource for repository : ${repository}")
                                    updateResult = service.update(updateInventoryRequest)
                                    logResult(updateResult)
                                } else if (checkPoliciesResult != null) {
                                    log.info("Sending Update to WhiteSource for repository : ${repository}")
                                    if (!checkPoliciesResult.hasRejections()) {
                                        updateResult = service.update(updateInventoryRequest)
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
                }
                deleteTemporaryFolders(archiveFilesDirectories)
            }
        } catch (Exception e) {
            log.warn("Error while running whitesource-plugin: ", e)
        } finally {
            log.info("Job updateRepoWithWhiteSource has Finished")
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
                def triggerAfterCreate = true
                def archiveExtractionDepth = config.containsKey(ARCHIVE_EXTRACTION_DEPTH) ? config.get(ARCHIVE_EXTRACTION_DEPTH) : ARCHIVE_EXTRACTION_DEPTH_DEFAULT
                archiveExtractionDepth = verifyArchiveExtractionDepth(archiveExtractionDepth)

                if (config.containsKey('triggerAfterCreate')) {
                    triggerBeforeDownload = config.triggerAfterCreate
                }
                if (triggerAfterCreate) {
                    Map<String, WssItemInfo> sha1ToItemMap = new HashMap<String, WssItemInfo>()
                    sha1ToItemMap.put(repositories.getFileInfo(item.getRepoPath()).getChecksumsInfo().getSha1(), new WssItemInfo(item.getName(), item.getRepoPath()))
                    List<File> fileList = new ArrayList<>()
                    String[] includesRepositoryContent = []
                    Set<String> allowedFileExtensions = new HashSet<String>()
                    def repoKey = item.getRepoKey()
                    Collection<AgentProjectInfo> projects = createProjects(sha1ToItemMap, repoKey, fileList, includesRepositoryContent, allowedFileExtensions, archiveExtractionDepth)
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
            }
        } catch (Exception e) {
            log.warn("Error creating WhiteSource Service " + e)
        }
    }
}

/* --- Private Methods --- */

private void deleteTemporaryFolders(List<File> compressedFilesFolder) {
    try {
        File fileExtractorTempFolder = new File(TEMP_DOWNLOAD_DIRECTORY + File.separator + "WhiteSource-ArchiveExtractor")
        if (fileExtractorTempFolder.exists()) {
            //the temp folder used by the WSS file agent is present.
            deleteNonEmptyDirectory(fileExtractorTempFolder)
        }

        // Deleting compressed file and parent folder
        if (compressedFilesFolder != null && compressedFilesFolder.size() > 0) {
            for (int i = 0; i < compressedFilesFolder.size(); i++) {
                File toRemove = compressedFilesFolder.get(i)
                deleteNonEmptyDirectory(toRemove.getParentFile())
            }
        }
    } catch (Exception e) {
        log.warn("Error during deleting of whitesource temporary files " + e)
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

/*
 * Get archive includes extension from properties file
 * If is empty then use default archive includes array
 */

private Set<String> getArchiveIncludes(String[] allowedFileExtensionsFromConfigFile, boolean withPrefix) {
    Set<String> archiveIncludes = new HashSet<String>()
    for (String key : allowedFileExtensionsFromConfigFile) {
        if (withPrefix) {
            key = PREFIX + key
        }
        archiveIncludes.add(key)
    }

    if (archiveIncludes.size() == 0) {
        String tempPrefix = PREFIX
        if (withPrefix) {
            tempPrefix = ""
        }

        // If archiveIncludes isn't provided in properties file, Use the default archive includes array
        ARCHIVE_INCLUDES_DEFAULT.each { archiveExtension ->
            archiveIncludes.add(tempPrefix + archiveExtension)
        }
    }

    return archiveIncludes
}

private void handleCheckPoliciesResults(Map<String, PolicyCheckResourceNode> projects, Map<String, WssItemInfo> sha1ToItemMap) {
    for (String key : projects.keySet()) {
        PolicyCheckResourceNode policyCheckResourceNode = projects.get(key)
        Collection<PolicyCheckResourceNode> children = policyCheckResourceNode.getChildren()
        for (PolicyCheckResourceNode child : children) {
            WssItemInfo wssItemInfo = sha1ToItemMap.get(child.getResource().getSha1())
            if (wssItemInfo != null && child.getPolicy() != null) {
                def path = wssItemInfo.getRepoPath()
                if (REJECT.equals(child.getPolicy().getActionType()) || ACCEPT.equals(child.getPolicy().getActionType())) {
                    repositories.setProperty(path, ACTION, child.getPolicy().getActionType())
                    repositories.setProperty(path, POLICY_DETAILS, child.getPolicy().getDisplayName())
                }
            }
        }
    }
}

private updateItemsExtraData(GetDependencyDataResult dependencyDataResult, Map<String, WssItemInfo> sha1ToItemMap) {
    for (ResourceInfo resource : dependencyDataResult.getResources()) {
        WssItemInfo wssItemInfo = sha1ToItemMap.get(resource.getSha1())
        if (wssItemInfo != null) {
            RepoPath repoPath = wssItemInfo.getRepoPath()
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

/*
 * Add all repository children (files) to hash map 'sha1ToItemMap'
 * If child file is type of archive that is included in archiveIncludes then add it to 'archiveFilesList'
 *
 * @param repoPath - repository path
 * @param sha1ToItemMap -  Map contains repositories content, Sha1 is the key for each item
 * @param archiveFilesList - If item extension is one of the archiveIncludes (archive extensions includes)
 * @param archiveIncludes - Archive extensions includes from config file
 */

private void findAllRepositoryItems(
        def repoPath, Map<String, WssItemInfo> sha1ToItemMap, List<ItemInfo> archiveFilesList, Set<String> archiveIncludes = null) {
    if (archiveIncludes == null || archiveIncludes.size() == 0) {
        log.error("No includes file extensions list was provided.")
        return
    }

    // Loop over repository all children, If children is folder loop over its children too
    for (ItemInfo item : repositories.getChildren(repoPath)) {
        if (item.isFolder()) {
            findAllRepositoryItems(item.getRepoPath(), sha1ToItemMap, archiveFilesList, archiveIncludes)
        } else {
            String endsWith = item.getName()
            int index = endsWith.lastIndexOf(".")

            // Save item in sha1 hashMap
            sha1ToItemMap.put(repositories.getFileInfo(item.getRepoPath()).getChecksumsInfo().getSha1(), new WssItemInfo(item.getName(), item.getRepoPath()))
            if (item.getName().lastIndexOf(".") > -1) {
                endsWith = endsWith.substring(index + 1)
                if (archiveIncludes.contains(endsWith)) {
                    archiveFilesList.add(item.getRepoPath())
                }
            }
        }
    }
}

private void populateArtifactoryPropertiesTab(Collection<AgentProjectInfo> projects, def config, String repoName,
                                              WhitesourceService whitesourceService, Map<String, WssItemInfo> sha1ToItemMap,
                                              CheckPolicyComplianceResult checkPoliciesResult, String productName, String userKey) {
    // get policies and dependency data result and update properties tab for each artifact
    try {
        int repoSize = sha1ToItemMap.size()
        log.info("Finished updating WhiteSource with ${repoSize} artifacts")
        GetDependencyDataRequest dependencyDataRequest = new GetDependencyDataRequest(config.apiKey, productName, BLANK, projects)
        dependencyDataRequest.setUserKey(userKey)
        GetDependencyDataResult dependencyDataResult = whitesourceService.getDependencyData(dependencyDataRequest)
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

private Collection<AgentProjectInfo> createProjects(Map<String, WssItemInfo> sha1ToItemMap, String repositoryName, List<File> archiveFilesDirectories,
                                                    String[] includesExtensions, Set<String> archiveIncludesWithPrefix, int archiveExtractionDepth) {

    List<String> uncompressedArchiveDirectories = new ArrayList<String>()
    List<DependencyInfo> dependencies = new ArrayList<DependencyInfo>()
    Collection<AgentProjectInfo> projects = new ArrayList<AgentProjectInfo>()

    AgentProjectInfo projectInfo = new AgentProjectInfo()
    projects.add(projectInfo)
    projectInfo.setCoordinates(new Coordinates(null, repositoryName, BLANK))

    for (String key : sha1ToItemMap.keySet()) {
        DependencyInfo dependencyInfo = new DependencyInfo(key)
        String itemName = sha1ToItemMap.get(key).getName()
        dependencyInfo.setArtifactId(itemName)
        dependencies.add(dependencyInfo)


        String[] archiveIncludesArray = archiveIncludesWithPrefix.toArray(new String[archiveIncludesWithPrefix.size()])

        File compressedFile
        // If this repository item is archive file, Use UA to extract and scan contents (Files from 'includes' extension)
        for (int i = 0; i < archiveFilesDirectories.size(); i++) {
            compressedFile = archiveFilesDirectories.get(i)

            // If item is one fo the compressedFiles taken from repository
            if (compressedFile.getPath().toString().endsWith(itemName)) {

                // Extract archive file
                String[] exclude = [itemName]
                def compressedFilesFolderCanonicalPath = compressedFile.getCanonicalPath()
                ArchiveExtractor archiveExtractor = new ArchiveExtractor(archiveIncludesArray, new String[0], exclude, false);
                String unpackDirectory = archiveExtractor.extractArchives(compressedFilesFolderCanonicalPath, archiveExtractionDepth, uncompressedArchiveDirectories);

                new File(unpackDirectory).eachFileRecurse(FILES) {
                    if (it.name.endsWithAny(includesExtensions)) {
                        try {
                            String fileSha1 = ChecksumUtils.calculateSHA1(it);
                            DependencyInfo childDependencyInfo = new DependencyInfo(fileSha1)
                            childDependencyInfo.setArtifactId(it.name)
                            dependencyInfo.getChildren().add(childDependencyInfo)
                        } catch (Exception e){
                            log.warn("Failed to calculate sha1 for '"+ it.name+"'")
                        }
                    }
                }

                deleteNonEmptyDirectory(new File(unpackDirectory).getParentFile())
                break
            }
        }
    }
    projectInfo.setDependencies(dependencies)
    return projects
}

private CheckPolicyComplianceResult checkPolicies(WhitesourceService service, String orgToken, String product, String productVersion,
                                                  Collection<AgentProjectInfo> projects, boolean forceCheckAllDependencies, boolean forceUpdate, String userKey) {
    log.info("Checking policies")
    CheckPolicyComplianceResult checkPoliciesResult = null
    try {
        CheckPolicyComplianceRequest policyComplianceRequest = new CheckPolicyComplianceRequest(orgToken, product, productVersion, projects, forceCheckAllDependencies, userKey,
                null, null, null)
        checkPoliciesResult = service.checkPolicyCompliance(policyComplianceRequest)
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


/*
 * Clone archive file from artifactory repository to local temp directory
 */
private List<File> cloneArchiveFilesToTempDirectory(List archiveFilesList, String repository) throws IOException {
    List<File> listOfArchiveFiles = new ArrayList<>()

    for (int i = 0; i < archiveFilesList.size(); i++) {
        inputStream = null
        dstArchiveFileOutputStream = null
        def artifactName = archiveFilesList.get(i).getPath().substring(archiveFilesList.get(i).getPath().lastIndexOf(BACK_SLASH) + 1)
        File destDir = new File(TEMP_DOWNLOAD_DIRECTORY + File.separator + repository + System.nanoTime() + File.separator + artifactName)

        if (!destDir.exists()) {
            destDir.mkdirs()
        }

        // Copy repository archive file from artifactory to dst archive file
        def inputStream
        def dstArchiveFileOutputStream
        try {
            inputStream = repositories.getContent(archiveFilesList.get(i)).getInputStream()
            dstArchiveFileOutputStream = new File(destDir.getPath() + File.separator + artifactName).newOutputStream()

            dstArchiveFileOutputStream << inputStream
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close()
                } catch (Exception e) {
                }
            }
            if (dstArchiveFileOutputStream != null) {
                try {
                    dstArchiveFileOutputStream.close()
                } catch (Exception e) {
                }
            }
        }
        listOfArchiveFiles.add(destDir)
    }
    return listOfArchiveFiles
}

private String[] buildDefaults() {
    String[] defaultArray = [
            "as", "asp", "aspx", "c", "h", "s", "cc", "cp", "cpp", "cxx", "c++", "hpp", "hxx", "h++", "hh", "mm", "c#", "cs",
            "csharp", "go", "goc", "html", "m", "pch", "java", "js", "jsp", "pl", "plx", "pm", "ph", "cgi", "fcgi", "psgi",
            "al", "perl", "t", "p6m", "p6l", "nqp", "6pl", "6pm", "p6", "php", "py", "rb", "swift", "clj", "cljc", "cljs",
            "cljx", "y", "jar", "war", "aar", "ear", "dll", "exe", "msi", "gem", "egg", "tar.gz", "whl", "rpm", "deb", "drpm",
            "dmg", "udeb", "so", "ko", "a", "ar", "nupkg", "air", "apk", "swc", "swf", "bz2", "gzip", "tar.bz2", "tgz", "zip"]
    return defaultArray
}

private String[] addPrefix(String[] values) {
    String[] updated = new String[values.size()]
    for (int i = 0; i < values.size(); i++) {
        updated[i] = "." + values[i]
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
            def status = 409
//            def status = 403
            def message = "${artifactName} did not conform with open source policies :  ${name}"
            log.warn message
            throw new CancelException(message, status)
//            {
//                public Throwable fillInStackTrace() {
////                    return
//                }
//
//            }
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

private String getRemoteRepoFileSha1(def conf, def rpath) {
    def url = conf.url
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

private int verifyArchiveExtractionDepth(int archiveExtractionDepth) {
    if (archiveExtractionDepth < ARCHIVE_EXTRACTION_DEPTH_MIN) {
        archiveExtractionDepth = ARCHIVE_EXTRACTION_DEPTH_MIN
        log.warn("Minimum archive extraction depth is ${ARCHIVE_EXTRACTION_DEPTH_MIN}, Archive extraction depth was set up to minimum value.")
    } else if (archiveExtractionDepth > ARCHIVE_EXTRACTION_DEPTH_MAX) {
        archiveExtractionDepth = ARCHIVE_EXTRACTION_DEPTH_MAX
        log.warn("Maximum archive extraction depth is ${ARCHIVE_EXTRACTION_DEPTH_MAX}, Archive extraction depth was set up to maximum value.")
    }
    return archiveExtractionDepth
}

/*
 * Internal class
 */
class WssItemInfo {
    String name
    RepoPath repoPath

    WssItemInfo(name, repoPath) {
        this.name = name
        this.repoPath = repoPath
    }

    String getName() {
        return this.name
    }

    RepoPath getRepoPath() {
        return this.repoPath
    }
}
