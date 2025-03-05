/**
 * @name VirusTotalScanner
 * @author Crux4000
 * @description Advanced link scanning using VirusTotal API with collection and graph management
 * @version 0.5.0
 * @website https://github.com/Crux4000/BetterDiscordPlugins
 * @source https://github.com/Crux4000/BetterDiscordPlugins
 */

// Collection Manager - For creating and managing VirusTotal collections and graphs
class VirusTotalCollectionManager {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.baseUrl = 'https://www.virustotal.com/api/v3';
    }

    // Check if the API key has Enterprise capabilities
    async checkApiPermissions() {
        try {
            const response = await BdApi.Net.fetch(`${this.baseUrl}/users/current`, {
                method: 'GET',
                headers: {
                    'x-apikey': this.apiKey,
                    'accept': 'application/json'
                }
            });
            
            if (!response.ok) {
                console.error(`API permissions check failed: ${response.statusText}`);
                return { enterprise: false, message: `API permissions check failed: ${response.statusText}` };
            }
            
            const userData = await response.json();
            console.log("User data:", userData);
            
            // Check if the user has enterprise capabilities
            const userType = userData?.data?.attributes?.privileges?.level || "free";
            const isEnterprise = userType !== "free";
            
            return { 
                enterprise: isEnterprise,
                message: isEnterprise ? 
                    "Enterprise account detected" : 
                    "Free account detected - collections and graphs may not be available"
            };
        } catch (error) {
            console.error("API permissions check error:", error);
            return { enterprise: false, message: `Error checking API permissions: ${error.message}` };
        }
    }

    // Add file or URL to a collection based on the input type
    async addItemToCollection(collectionId, item, itemType = 'url') {
        // Check if we're dealing with a local collection
        if (collectionId.startsWith('local-')) {
            return this.addUrlToLocalCollection(collectionId, item);
        }
        
        try {
            // Determine the endpoint based on item type
            const endpoint = itemType === 'file' ? 
                `${this.baseUrl}/intelligence/collections/${collectionId}/files` : 
                `${this.baseUrl}/intelligence/collections/${collectionId}/urls`;
            
            console.log(`Adding ${itemType} to collection: ${item} to ${collectionId} using endpoint ${endpoint}`);
            
            // Prepare the request body based on item type
            const requestBody = {
                data: [{
                    type: itemType,
                    // For files we use 'id', for URLs we use 'url'
                    ...(itemType === 'file' ? { id: item } : { url: item })
                }]
            };
            
            const response = await BdApi.Net.fetch(endpoint, {
                method: 'POST',
                headers: {
                    'x-apikey': this.apiKey,
                    'Content-Type': 'application/json',
                    'accept': 'application/json'
                },
                body: JSON.stringify(requestBody)
            });

            if (!response.ok) {
                console.log(`Failed to add ${itemType} to collection: ${response.statusText}`);
                
                // If this is a file and the request failed, try as a URL instead
                if (itemType === 'file') {
                    console.log(`Retrying as URL...`);
                    // Get the original URL from local storage if possible
                    return this.addItemToCollection(collectionId, item, 'url');
                }
                
                throw new Error(`Failed to add ${itemType} to collection: ${response.statusText}`);
            }

            return true;
        } catch (error) {
            console.error(`${itemType} addition to collection error:`, error);
            // If enterprise API failed, try the local approach as fallback
            if (!collectionId.startsWith('local-')) {
                console.log('Enterprise API failed, falling back to local collection');
                return this.addUrlToLocalCollection(collectionId, item);
            }
            throw error;
        }
    }

    // Add a file to a collection
    async addFileToCollection(collectionId, fileHash) {
        try {
            console.log(`Adding file to collection: ${fileHash} to ${collectionId}`);
            
            const response = await BdApi.Net.fetch(`${this.baseUrl}/intelligence/collections/${collectionId}/files`, {
                method: 'POST',
                headers: {
                    'x-apikey': this.apiKey,
                    'Content-Type': 'application/json',
                    'accept': 'application/json'
                },
                body: JSON.stringify({
                    data: [{
                        type: "file",
                        id: fileHash
                    }]
                })
            });

            if (!response.ok) {
                throw new Error(`Failed to add file to collection: ${response.statusText}`);
            }

            return true;
        } catch (error) {
            console.error('File addition to collection error:', error);
            throw error;
        }
    }

    // Create a new collection (or store in local data)
    async createCollection(name, description = '') {
        try {
            // First try to check permissions
            const permissions = await this.checkApiPermissions();
            console.log("API permissions:", permissions);
            
            // For Enterprise accounts, try to create a collection
            if (permissions.enterprise) {
                // Use exact format from the example
                const response = await BdApi.Net.fetch(`${this.baseUrl}/intelligence/collections`, {
                    method: 'POST',
                    headers: {
                        'x-apikey': this.apiKey,
                        'Content-Type': 'application/json',
                        'accept': 'application/json'
                    },
                    body: JSON.stringify({
                        data: {
                            attributes: {
                                name: name,
                                description: description || `Malicious files detected by Discord VirusTotal Scanner`
                            },
                            type: "collection"
                        }
                    })
                });

                if (!response.ok) {
                    // If enterprise but still can't create collection, fall back to local
                    console.error(`Failed to create collection: ${response.statusText}`);
                    return this.createLocalCollection(name, description);
                }

                const result = await response.json();
                console.log("Collection creation response:", result);
                
                return {
                    id: result.data.id,
                    name: result.data.attributes.name,
                    description: result.data.attributes.description,
                    isLocal: false
                };
            } else {
                // For free accounts, use local storage
                return this.createLocalCollection(name, description);
            }
        } catch (error) {
            console.error('Collection creation error:', error);
            // Fall back to local collection
            return this.createLocalCollection(name, description);
        }
    }
    
    // Create a local collection
    createLocalCollection(name, description = '') {
        // Generate a unique ID
        const collectionId = 'local-' + Date.now().toString();
        
        // Create a collection object
        const collection = {
            id: collectionId,
            name: name,
            description: description || `Malicious files detected by Discord VirusTotal Scanner`,
            items: [],
            isLocal: true
        };
        
        // Save to local storage
        const collections = BdApi.getData("VirusTotalScanner", "collections") || [];
        collections.push(collection);
        BdApi.saveData("VirusTotalScanner", "collections", collections);
        
        console.log(`Created local collection: ${name} with ID ${collectionId}`);
        return collection;
    }

    // Add a URL to a collection
    async addUrlToCollection(collectionId, url) {
        console.log(`Adding URL to collection: ${url} to ${collectionId}`);
        
        // Check if this is a local collection (ID starts with 'local-')
        if (collectionId.startsWith('local-')) {
            return this.addUrlToLocalCollection(collectionId, url);
        }
        
        try {
            // For VirusTotal collections
            const response = await BdApi.Net.fetch(`${this.baseUrl}/intelligence/collections/${collectionId}/urls`, {
                method: 'POST',
                headers: {
                    'x-apikey': this.apiKey,
                    'Content-Type': 'application/json',
                    'accept': 'application/json'
                },
                body: JSON.stringify({
                    data: [{
                        type: "url",
                        url: url
                    }]
                })
            });

            if (!response.ok) {
                throw new Error(`Failed to add URL to collection: ${response.statusText}`);
            }

            return true;
        } catch (error) {
            console.error('URL addition to collection error:', error);
            throw error;
        }
    }
    
    // Add URL to local collection
    addUrlToLocalCollection(collectionId, url) {
        // Get the collections from local storage
        const collections = BdApi.getData("VirusTotalScanner", "collections") || [];
        
        // Find the collection
        const collection = collections.find(c => c.id === collectionId);
        if (!collection) {
            throw new Error(`Local collection not found: ${collectionId}`);
        }
        
        // Add the URL to the collection if it's not already there
        if (!collection.items.includes(url)) {
            collection.items.push(url);
            
            // Save back to local storage
            BdApi.saveData("VirusTotalScanner", "collections", collections);
            console.log(`Added URL to local collection: ${url} to ${collection.name}`);
        }
        
        return true;
    }

    // Create a graph (or store in local data)
    async createFileGraph(name, description = '') {
        try {
            // First try to check permissions
            const permissions = await this.checkApiPermissions();
            console.log("API permissions:", permissions);
            
            // For Enterprise accounts, try to create a graph
            if (permissions.enterprise) {
                const response = await BdApi.Net.fetch(`${this.baseUrl}/intelligence/graphs`, {
                    method: 'POST',
                    headers: {
                        'x-apikey': this.apiKey,
                        'Content-Type': 'application/json',
                        'accept': 'application/json'
                    },
                    body: JSON.stringify({
                        data: {
                            attributes: {
                                name: name,
                                description: description || `Malicious file relationships from Discord VirusTotal Scanner`
                            },
                            type: "graph"
                        }
                    })
                });

                if (!response.ok) {
                    // If enterprise but still can't create graph, fall back to local
                    console.error(`Failed to create graph: ${response.statusText}`);
                    return this.createLocalGraph(name, description);
                }

                const result = await response.json();
                console.log("Graph creation response:", result);
                
                return {
                    id: result.data.id,
                    name: result.data.attributes.name,
                    description: result.data.attributes.description,
                    isLocal: false
                };
            } else {
                // For free accounts, use local storage
                return this.createLocalGraph(name, description);
            }
        } catch (error) {
            console.error('Graph creation error:', error);
            // Fall back to local graph
            return this.createLocalGraph(name, description);
        }
    }
    
    // Create a local graph
    createLocalGraph(name, description = '') {
        // Generate a unique ID
        const graphId = 'local-' + Date.now().toString();
        
        // Create a graph object
        const graph = {
            id: graphId,
            name: name,
            description: description || `Malicious file relationships from Discord VirusTotal Scanner`,
            relationships: [],
            isLocal: true
        };
        
        // Save to local storage
        const graphs = BdApi.getData("VirusTotalScanner", "graphs") || [];
        graphs.push(graph);
        BdApi.saveData("VirusTotalScanner", "graphs", graphs);
        
        console.log(`Created local graph: ${name} with ID ${graphId}`);
        return graph;
    }

    // Add a relationship to a graph
    async addRelationshipToGraph(graphId, sourceUrl, targetUrl, relationship) {
        console.log(`Adding relationship to graph: ${sourceUrl} to ${targetUrl} in ${graphId}`);
        
        // Check if this is a local graph (ID starts with 'local-')
        if (graphId.startsWith('local-')) {
            return this.addRelationshipToLocalGraph(graphId, sourceUrl, targetUrl, relationship);
        }
        
        try {
            // For VirusTotal graphs
            const response = await BdApi.Net.fetch(`${this.baseUrl}/intelligence/graphs/${graphId}/relationships`, {
                method: 'POST',
                headers: {
                    'x-apikey': this.apiKey,
                    'Content-Type': 'application/json',
                    'accept': 'application/json'
                },
                body: JSON.stringify({
                    data: [{
                        type: "relationship",
                        attributes: {
                            source_type: "url",
                            source_url: sourceUrl,
                            target_type: "url",
                            target_url: targetUrl,
                            relationship_type: relationship
                        }
                    }]
                })
            });

            if (!response.ok) {
                throw new Error(`Failed to add relationship to graph: ${response.statusText}`);
            }

            return true;
        } catch (error) {
            console.error('Relationship addition to graph error:', error);
            throw error;
        }
    }
    
    // Add relationship to local graph
    addRelationshipToLocalGraph(graphId, sourceUrl, targetUrl, relationship) {
        // Get the graphs from local storage
        const graphs = BdApi.getData("VirusTotalScanner", "graphs") || [];
        
        // Find the graph
        const graph = graphs.find(g => g.id === graphId);
        if (!graph) {
            throw new Error(`Local graph not found: ${graphId}`);
        }
        
        // Check if this relationship already exists
        const relationshipExists = graph.relationships.some(
            r => r.source === sourceUrl && r.target === targetUrl
        );
        
        // Add the relationship if it doesn't exist
        if (!relationshipExists) {
            graph.relationships.push({
                source: sourceUrl,
                target: targetUrl,
                type: relationship,
                date: new Date().toISOString()
            });
            
            // Save back to local storage
            BdApi.saveData("VirusTotalScanner", "graphs", graphs);
            console.log(`Added relationship to local graph: ${sourceUrl} to ${targetUrl} in ${graph.name}`);
        }
        
        return true;
    }
}

// File Tracker - For tracking files and managing auto-tracking features
class VirusTotalFileTracker {
    constructor(mainPlugin) {
        this.mainPlugin = mainPlugin;
        this.collectionManager = null;
    }

    // Get existing collections from local storage
    getExistingCollections() {
        return BdApi.getData("VirusTotalScanner", "collections") || [];
    }

    // Get existing graphs from local storage
    getExistingGraphs() {
        return BdApi.getData("VirusTotalScanner", "graphs") || [];
    }

    // Determine file status based on scan results
    determineFileStatus(scanResult) {
        if (!scanResult) return 'unknown';

        if (scanResult.malicious > 0) return 'malicious';
        if (scanResult.suspicious > 0) return 'suspicious';
        return 'clean';
    }

    // Modify tooltip to include add to collection/graph buttons
    modifyTooltip(tooltipElement, fileHash, scanResult) {
        console.log(`[VirusTotalFileTracker] Modifying tooltip for: ${fileHash}`);
        
        // Initialize collection manager
        if (!this.collectionManager) {
            this.collectionManager = new VirusTotalCollectionManager(this.mainPlugin.apiKey);
        }

        // Get existing collections and graphs
        const collections = this.getExistingCollections();
        const graphs = this.getExistingGraphs();

        // Add collections and graphs information to tooltip
        let content = "";
        
        // Add collection counts if any exist
        if (collections.length > 0) {
            // Count how many collections this URL is in
            const collectionsWithUrl = collections.filter(
                c => c.items && c.items.includes(fileHash)
            );
            
            if (collectionsWithUrl.length > 0) {
                content += `<div style="margin-top: 4px; font-size: 12px;">In ${collectionsWithUrl.length} collection(s)</div>`;
            }
        }
        
        // Add graph counts if any exist
        if (graphs.length > 0) {
            // Count how many graphs this URL is in
            const graphsWithUrl = graphs.filter(
                g => g.relationships && g.relationships.some(r => r.source === fileHash || r.target === fileHash)
            );
            
            if (graphsWithUrl.length > 0) {
                content += `<div style="margin-top: 4px; font-size: 12px;">In ${graphsWithUrl.length} graph(s)</div>`;
            }
        }
        
        // Add this information to tooltip if we have any
        if (content) {
            const infoSection = document.createElement("div");
            infoSection.className = "vt-tracking-info";
            infoSection.style.marginTop = "8px";
            infoSection.style.borderTop = "1px solid rgba(255, 255, 255, 0.1)";
            infoSection.style.paddingTop = "8px";
            infoSection.innerHTML = content;
            tooltipElement.appendChild(infoSection);
        }

        console.log(`[VirusTotalFileTracker] Found collections: ${collections.length}, graphs: ${graphs.length}`);

        // Only add dropdowns if there are collections or graphs
        if (collections.length === 0 && graphs.length === 0) {
            console.log("[VirusTotalFileTracker] No collections or graphs found, not adding dropdowns");
            return;
        }

        // Create container for dropdowns
        const dropdownContainer = document.createElement("div");
        dropdownContainer.className = "vt-dropdown-container";
        dropdownContainer.style.marginTop = "8px";
        dropdownContainer.style.borderTop = "1px solid rgba(255, 255, 255, 0.1)";
        dropdownContainer.style.paddingTop = "8px";

        // Create collection dropdown
        if (collections.length > 0) {
            const collectionsDropdown = document.createElement("select");
            collectionsDropdown.className = "vt-dropdown";
            collectionsDropdown.style.width = "100%";
            collectionsDropdown.style.marginBottom = "5px";
            collectionsDropdown.style.padding = "4px";
            collectionsDropdown.style.backgroundColor = "var(--background-secondary)";
            collectionsDropdown.style.color = "var(--text-normal)";
            collectionsDropdown.style.border = "1px solid var(--background-tertiary)";
            collectionsDropdown.style.borderRadius = "4px";
            collectionsDropdown.innerHTML = `
                <option value="">Add to Collection</option>
                ${collections.map(c => {
                    // Check if URL is already in this collection
                    const isInCollection = c.items && c.items.includes(fileHash);
                    // Disable options for collections that already contain the URL
                    return `<option value="${c.id}" ${isInCollection ? 'disabled' : ''}>${c.name}${isInCollection ? ' ✓' : ''}</option>`;
                }).join('')}
            `;

            collectionsDropdown.addEventListener("change", async (e) => {
                const collectionId = e.target.value;
                if (!collectionId) return;

                try {
                    const result = await this.collectionManager.addUrlToCollection(collectionId, fileHash);
                    
                    if (result) {
                        BdApi.showToast(`Added to collection`, { type: "success" });
                        // Disable this option now that it's been added
                        const option = collectionsDropdown.querySelector(`option[value="${collectionId}"]`);
                        if (option) {
                            option.disabled = true;
                            option.textContent += " ✓";
                        }
                        e.target.selectedIndex = 0;
                    } else {
                        BdApi.showToast(`Failed to add to collection`, { type: "error" });
                    }
                } catch (error) {
                    console.error("Collection addition error:", error);
                    BdApi.showToast(`Error adding to collection`, { type: "error" });
                }
            });

            dropdownContainer.appendChild(collectionsDropdown);
        }

        // Create graph dropdown
        if (graphs.length > 0) {
            const graphsDropdown = document.createElement("select");
            graphsDropdown.className = "vt-dropdown";
            graphsDropdown.style.width = "100%";
            graphsDropdown.style.padding = "4px";
            graphsDropdown.style.backgroundColor = "var(--background-secondary)";
            graphsDropdown.style.color = "var(--text-normal)";
            graphsDropdown.style.border = "1px solid var(--background-tertiary)";
            graphsDropdown.style.borderRadius = "4px";
            graphsDropdown.innerHTML = `
                <option value="">Add to Graph</option>
                ${graphs.map(g => {
                    // Check if URL is already in this graph
                    const isInGraph = g.relationships && g.relationships.some(
                        r => r.source === fileHash || r.target === fileHash
                    );
                    // Disable options for graphs that already contain the URL
                    return `<option value="${g.id}" ${isInGraph ? 'disabled' : ''}>${g.name}${isInGraph ? ' ✓' : ''}</option>`;
                }).join('')}
            `;

            graphsDropdown.addEventListener("change", async (e) => {
                const graphId = e.target.value;
                if (!graphId) return;

                try {
                    // Determine file status for relationship type
                    const fileStatus = this.determineFileStatus(scanResult);

                    const result = await this.collectionManager.addRelationshipToGraph(
                        graphId, 
                        fileHash, 
                        fileHash, 
                        fileStatus
                    );
                    
                    if (result) {
                        BdApi.showToast(`Added to graph`, { type: "success" });
                        // Disable this option now that it's been added
                        const option = graphsDropdown.querySelector(`option[value="${graphId}"]`);
                        if (option) {
                            option.disabled = true;
                            option.textContent += " ✓";
                        }
                        e.target.selectedIndex = 0;
                    } else {
                        BdApi.showToast(`Failed to add to graph`, { type: "error" });
                    }
                } catch (error) {
                    console.error("Graph addition error:", error);
                    BdApi.showToast(`Error adding to graph`, { type: "error" });
                }
            });

            dropdownContainer.appendChild(graphsDropdown);
        }

        // Add dropdown container to tooltip
        tooltipElement.appendChild(dropdownContainer);
    }

    // Add auto-tracking settings to the plugin settings
    addAutoTrackingSettings(panel) {
        const autoTrackSection = document.createElement("div");
        autoTrackSection.className = "vt-auto-track-section";
        autoTrackSection.style.marginTop = "20px";
        autoTrackSection.style.padding = "10px";
        autoTrackSection.style.borderTop = "1px solid var(--background-modifier-accent)";

        const sectionTitle = document.createElement("h3");
        sectionTitle.textContent = "Automatic File Tracking";
        autoTrackSection.appendChild(sectionTitle);

        // Auto-track collections toggle
        const collectionsTrackGroup = document.createElement("div");
        collectionsTrackGroup.className = "vt-settings-group";
        collectionsTrackGroup.style.marginBottom = "10px";

        const collectionsTrackLabel = document.createElement("label");
        collectionsTrackLabel.textContent = "Automatically add files to first collection";
        
        const collectionsTrackToggle = document.createElement("div");
        collectionsTrackToggle.className = "vt-toggle";

        // Get current settings
        const currentSettings = BdApi.getData("VirusTotalScanner", "autoTrack") || {
            collections: false,
            graphs: false
        };

        // Set initial state
        collectionsTrackToggle.classList.toggle("vt-toggle-checked", currentSettings.collections);

        // Toggle click handler
        collectionsTrackToggle.addEventListener("click", () => {
            const isCurrentlyChecked = collectionsTrackToggle.classList.contains("vt-toggle-checked");
            collectionsTrackToggle.classList.toggle("vt-toggle-checked", !isCurrentlyChecked);
            
            // Update settings
            const updatedSettings = {
                ...currentSettings,
                collections: !isCurrentlyChecked
            };
            
            BdApi.saveData("VirusTotalScanner", "autoTrack", updatedSettings);
        });

        collectionsTrackGroup.appendChild(collectionsTrackLabel);
        collectionsTrackGroup.appendChild(collectionsTrackToggle);
        autoTrackSection.appendChild(collectionsTrackGroup);

        // Auto-track graphs toggle
        const graphsTrackGroup = document.createElement("div");
        graphsTrackGroup.className = "vt-settings-group";

        const graphsTrackLabel = document.createElement("label");
        graphsTrackLabel.textContent = "Automatically add files to first graph";
        
        const graphsTrackToggle = document.createElement("div");
        graphsTrackToggle.className = "vt-toggle";

        // Set initial state
        graphsTrackToggle.classList.toggle("vt-toggle-checked", currentSettings.graphs);

        // Toggle click handler
        graphsTrackToggle.addEventListener("click", () => {
            const isCurrentlyChecked = graphsTrackToggle.classList.contains("vt-toggle-checked");
            graphsTrackToggle.classList.toggle("vt-toggle-checked", !isCurrentlyChecked);
            
            // Update settings
            const updatedSettings = {
                ...currentSettings,
                graphs: !isCurrentlyChecked
            };
            
            BdApi.saveData("VirusTotalScanner", "autoTrack", updatedSettings);
        });

        graphsTrackGroup.appendChild(graphsTrackLabel);
        graphsTrackGroup.appendChild(graphsTrackToggle);
        autoTrackSection.appendChild(graphsTrackGroup);

        // Add to main panel
        panel.appendChild(autoTrackSection);
    }

    // Method to process a file for tracking
    async processFile(fileHash, scanResult) {
        console.log(`[VirusTotalFileTracker] Processing file: ${fileHash}`);
        
        // Check if we have a file hash to use instead of the URL
        const identifierToUse = scanResult.fileHash || fileHash;
        const identifierType = scanResult.fileHash ? 'file' : 'url';
        
        if (scanResult.fileHash) {
            console.log(`[VirusTotalFileTracker] Using file hash for tracking: ${scanResult.fileHash}`);
        } else {
            console.log(`[VirusTotalFileTracker] No file hash available, using URL`);
        }
        
        // Automatically add to default collection/graph if configured
        const collections = this.getExistingCollections();
        const graphs = this.getExistingGraphs();

        console.log(`[VirusTotalFileTracker] Found collections: ${collections.length}, graphs: ${graphs.length}`);

        // Initialize collection manager
        if (!this.collectionManager) {
            this.collectionManager = new VirusTotalCollectionManager(this.mainPlugin.apiKey);
        }

        // Get user preference for auto-tracking
        const autoTrackSettings = BdApi.getData("VirusTotalScanner", "autoTrack") || {
            collections: false,
            graphs: false
        };

        console.log(`[VirusTotalFileTracker] Auto-track settings:`, autoTrackSettings);

        try {
            // Automatically add to first collection if enabled
            if (autoTrackSettings.collections && collections.length > 0) {
                console.log(`[VirusTotalFileTracker] Auto-adding to collection: ${collections[0].name}`);
                
                try {
                    // Use the unified method that handles both files and URLs
                    await this.collectionManager.addItemToCollection(
                        collections[0].id, 
                        identifierToUse,
                        identifierType
                    );
                    console.log(`[VirusTotalFileTracker] Successfully added to collection`);
                } catch (error) {
                    console.error(`[VirusTotalFileTracker] Failed to add to collection: ${error.message}`);
                }
            }

            // Automatically add to first graph if enabled
            if (autoTrackSettings.graphs && graphs.length > 0) {
                const fileStatus = this.determineFileStatus(scanResult);
                console.log(`[VirusTotalFileTracker] Auto-adding to graph: ${graphs[0].name} with status: ${fileStatus}`);
                
                try {
                    await this.collectionManager.addRelationshipToGraph(
                        graphs[0].id, 
                        identifierToUse, 
                        identifierToUse, 
                        fileStatus
                    );
                    console.log(`[VirusTotalFileTracker] Successfully added to graph`);
                } catch (error) {
                    console.error(`[VirusTotalFileTracker] Failed to add to graph: ${error.message}`);
                }
            }
        } catch (error) {
            console.error("Automatic file tracking error:", error);
        }
    }
}

// Settings Extension - For managing VirusTotal collections and graphs
class VirusTotalScannerSettingsExtension {
    constructor(mainPlugin) {
        this.mainPlugin = mainPlugin;
        this.collectionManager = null;
    }

    // Extend the settings panel to include multiple collections and graphs
    extendSettingsPanel(panel) {
        // Create a container for VirusTotal integration settings
        const vtIntegrationContainer = document.createElement("div");
        vtIntegrationContainer.className = "vt-integration-container";
        vtIntegrationContainer.style.marginTop = "20px";
        vtIntegrationContainer.style.padding = "10px";
        vtIntegrationContainer.style.borderTop = "1px solid var(--background-modifier-accent)";

        // Section for Collections
        const collectionsSection = this.createCollectionsSection();
        vtIntegrationContainer.appendChild(collectionsSection);

        // Section for Graphs
        const graphsSection = this.createGraphsSection();
        vtIntegrationContainer.appendChild(graphsSection);

        // Add to main panel
        panel.appendChild(vtIntegrationContainer);
    }

    createCollectionsSection() {
        const collectionsSection = document.createElement("div");
        collectionsSection.className = "vt-collections-section";
        collectionsSection.style.marginBottom = "20px";

        const sectionTitle = document.createElement("h3");
        sectionTitle.textContent = "VirusTotal Collections";
        collectionsSection.appendChild(sectionTitle);

        // Collections list
        const collectionsList = document.createElement("div");
        collectionsList.className = "vt-collections-list";
        collectionsList.style.marginTop = "10px";
        collectionsList.style.marginBottom = "10px";
        collectionsList.style.maxHeight = "150px";
        collectionsList.style.overflowY = "auto";
        collectionsList.style.border = "1px solid var(--background-modifier-accent)";
        collectionsList.style.borderRadius = "4px";
        collectionsList.style.padding = "5px";

        // Add Collection Button
        const addCollectionBtn = document.createElement("button");
        addCollectionBtn.textContent = "Add New Collection";
        addCollectionBtn.className = "vt-add-btn";
        addCollectionBtn.style.backgroundColor = "var(--brand-experiment)";
        addCollectionBtn.style.color = "white";
        addCollectionBtn.style.border = "none";
        addCollectionBtn.style.borderRadius = "4px";
        addCollectionBtn.style.padding = "8px 16px";
        addCollectionBtn.style.cursor = "pointer";
        addCollectionBtn.addEventListener("click", () => this.addNewCollection());
        collectionsSection.appendChild(addCollectionBtn);

        // Load existing collections
        this.loadExistingCollections(collectionsList);
        collectionsSection.appendChild(collectionsList);

        return collectionsSection;
    }

    createGraphsSection() {
        const graphsSection = document.createElement("div");
        graphsSection.className = "vt-graphs-section";

        const sectionTitle = document.createElement("h3");
        sectionTitle.textContent = "VirusTotal File Graphs";
        graphsSection.appendChild(sectionTitle);

        // Graphs list
        const graphsList = document.createElement("div");
        graphsList.className = "vt-graphs-list";
        graphsList.style.marginTop = "10px";
        graphsList.style.marginBottom = "10px";
        graphsList.style.maxHeight = "150px";
        graphsList.style.overflowY = "auto";
        graphsList.style.border = "1px solid var(--background-modifier-accent)";
        graphsList.style.borderRadius = "4px";
        graphsList.style.padding = "5px";

        // Add Graph Button
        const addGraphBtn = document.createElement("button");
        addGraphBtn.textContent = "Add New Graph";
        addGraphBtn.className = "vt-add-btn";
        addGraphBtn.style.backgroundColor = "var(--brand-experiment)";
        addGraphBtn.style.color = "white";
        addGraphBtn.style.border = "none";
        addGraphBtn.style.borderRadius = "4px";
        addGraphBtn.style.padding = "8px 16px";
        addGraphBtn.style.cursor = "pointer";
        addGraphBtn.addEventListener("click", () => this.addNewGraph());
        graphsSection.appendChild(addGraphBtn);

        // Load existing graphs
        this.loadExistingGraphs(graphsList);
        graphsSection.appendChild(graphsList);

        return graphsSection;
    }

    addNewCollection() {
        // Create BdApi input dialog
        BdApi.showConfirmationModal(
            "Create New Collection", 
            BdApi.React.createElement("div", {
                className: "vt-input-container",
                style: {
                    marginBottom: "10px"
                }
            }, [
                BdApi.React.createElement("input", {
                    id: "vt-collection-name-input",
                    type: "text",
                    placeholder: "Enter collection name",
                    style: {
                        width: "100%",
                        padding: "8px",
                        borderRadius: "4px",
                        border: "1px solid var(--background-tertiary, #2f3136)",
                        background: "var(--background-secondary, #36393f)",
                        color: "var(--text-normal, #dcddde)",
                        marginTop: "5px",
                        marginBottom: "5px"
                    }
                })
            ]),
            {
                confirmText: "Create",
                cancelText: "Cancel",
                onConfirm: async () => {
                    const collectionNameInput = document.getElementById("vt-collection-name-input");
                    const collectionName = collectionNameInput ? collectionNameInput.value : "";
                    
                    if (!collectionName) {
                        BdApi.showToast("Please enter a collection name", { type: "error" });
                        return;
                    }
                    
                    // Initialize collection manager
                    this.collectionManager = new VirusTotalCollectionManager(this.mainPlugin.apiKey);
                    
                    try {
                        const collection = await this.collectionManager.createCollection(collectionName);
                        
                        if (collection) {
                            // Collection is already saved in local storage if created locally
                            if (!collection.isLocal) {
                                // For VT API collections, save to local storage
                                const existingCollections = this.getExistingCollections();
                                existingCollections.push({
                                    id: collection.id,
                                    name: collection.name,
                                    description: collection.description,
                                    isLocal: false,
                                    created: new Date().toISOString()
                                });
                                this.saveExistingCollections(existingCollections);
                            }

                            BdApi.showToast(`Collection created: ${collection.name}${collection.isLocal ? ' (local)' : ''}`, { type: "success" });
                            
                            // Refresh the collections list
                            const collectionsList = document.querySelector('.vt-collections-list');
                            if (collectionsList) {
                                collectionsList.innerHTML = ''; // Clear existing list
                                this.loadExistingCollections(collectionsList);
                            }
                        }
                    } catch (error) {
                        BdApi.showToast(`Failed to create collection: ${error.message}`, { type: "error" });
                    }
                }
            }
        );
    }

    addNewGraph() {
        // Create BdApi input dialog
        BdApi.showConfirmationModal(
            "Create New File Graph", 
            BdApi.React.createElement("div", {
                className: "vt-input-container",
                style: {
                    marginBottom: "10px"
                }
            }, [
                BdApi.React.createElement("input", {
                    id: "vt-graph-name-input",
                    type: "text",
                    placeholder: "Enter graph name",
                    style: {
                        width: "100%",
                        padding: "8px",
                        borderRadius: "4px",
                        border: "1px solid var(--background-tertiary, #2f3136)",
                        background: "var(--background-secondary, #36393f)",
                        color: "var(--text-normal, #dcddde)",
                        marginTop: "5px",
                        marginBottom: "5px"
                    }
                })
            ]),
            {
                confirmText: "Create",
                cancelText: "Cancel",
                onConfirm: async () => {
                    const graphNameInput = document.getElementById("vt-graph-name-input");
                    const graphName = graphNameInput ? graphNameInput.value : "";
                    
                    if (!graphName) {
                        BdApi.showToast("Please enter a graph name", { type: "error" });
                        return;
                    }
                    
                    // Initialize collection manager
                    this.collectionManager = new VirusTotalCollectionManager(this.mainPlugin.apiKey);
                    
                    try {
                        const graph = await this.collectionManager.createFileGraph(graphName);
                        
                        if (graph) {
                            // Graph is already saved in local storage if created locally
                            if (!graph.isLocal) {
                                // For VT API graphs, save to local storage
                                const existingGraphs = this.getExistingGraphs();
                                existingGraphs.push({
                                    id: graph.id,
                                    name: graph.name,
                                    description: graph.description,
                                    isLocal: false,
                                    created: new Date().toISOString()
                                });
                                this.saveExistingGraphs(existingGraphs);
                            }

                            BdApi.showToast(`File graph created: ${graph.name}${graph.isLocal ? ' (local)' : ''}`, { type: "success" });
                            
                            // Refresh the graphs list
                            const graphsList = document.querySelector('.vt-graphs-list');
                            if (graphsList) {
                                graphsList.innerHTML = ''; // Clear existing list
                                this.loadExistingGraphs(graphsList);
                            }
                        }
                    } catch (error) {
                        BdApi.showToast(`Failed to create graph: ${error.message}`, { type: "error" });
                    }
                }
            }
        );
    }

    // Load existing collections from local storage
    loadExistingCollections(collectionsList) {
        const existingCollections = this.getExistingCollections();
        
        if (existingCollections.length === 0) {
            const noCollectionsMsg = document.createElement("p");
            noCollectionsMsg.textContent = "No collections created yet";
            noCollectionsMsg.className = "vt-empty-list";
            noCollectionsMsg.style.padding = "5px";
            noCollectionsMsg.style.color = "var(--text-muted)";
            collectionsList.appendChild(noCollectionsMsg);
            return;
        }

        existingCollections.forEach(collection => {
            // Count malicious and suspicious items
            let maliciousCount = 0;
            let suspiciousCount = 0;
            
            if (collection.items && Array.isArray(collection.items)) {
                collection.items.forEach(item => {
                    if (typeof item === 'object') {
                        if (item.status === 'malicious') maliciousCount++;
                        else if (item.status === 'suspicious') suspiciousCount++;
                    } else if (typeof item === 'string') {
                        if (item.startsWith('MALWARE-LINK:')) maliciousCount++;
                        else if (item.startsWith('SUSPICIOUS-LINK:')) suspiciousCount++;
                    }
                });
            }
            
            const collectionItem = document.createElement("div");
            collectionItem.className = "vt-collection-item";
            collectionItem.style.display = "flex";
            collectionItem.style.justifyContent = "space-between";
            collectionItem.style.alignItems = "center";
            collectionItem.style.padding = "5px";
            collectionItem.style.marginBottom = "5px";
            collectionItem.style.borderBottom = "1px solid var(--background-modifier-accent)";
            
            // Collection name and info
            const collectionInfo = document.createElement("div");
            collectionInfo.style.display = "flex";
            collectionInfo.style.flexDirection = "column";
            
            const collectionName = document.createElement("span");
            collectionName.textContent = collection.name;
            if (collection.isLocal) {
                collectionName.textContent += " (local)";
            }
            collectionInfo.appendChild(collectionName);
            
            const itemCount = document.createElement("span");
            itemCount.style.fontSize = "11px";
            itemCount.style.color = "var(--text-muted)";
            
            const totalItems = collection.items ? collection.items.length : 0;
            
            // Add threat counts if any exist
            let countText = `${totalItems} item${totalItems !== 1 ? 's' : ''}`;
            if (maliciousCount > 0 || suspiciousCount > 0) {
                countText += ` (${maliciousCount} malicious, ${suspiciousCount} suspicious)`;
            }
            
            itemCount.textContent = countText;
            collectionInfo.appendChild(itemCount);
            
            const collectionActions = document.createElement("div");
            collectionActions.className = "vt-collection-actions";
            
            // View button - show a list of items in the collection
            const viewBtn = document.createElement("button");
            viewBtn.textContent = "View";
            viewBtn.className = "vt-view-btn";
            viewBtn.style.backgroundColor = "var(--brand-experiment)";
            viewBtn.style.color = "white";
            viewBtn.style.border = "none";
            viewBtn.style.borderRadius = "4px";
            viewBtn.style.padding = "4px 8px";
            viewBtn.style.fontSize = "12px";
            viewBtn.style.marginRight = "5px";
            viewBtn.style.cursor = "pointer";
            viewBtn.addEventListener("click", () => this.viewCollection(collection));
            collectionActions.appendChild(viewBtn);

            // Delete button
            const deleteBtn = document.createElement("button");
            deleteBtn.textContent = "Delete";
            deleteBtn.className = "vt-delete-btn";
            deleteBtn.style.backgroundColor = "#f04747";
            deleteBtn.style.color = "white";
            deleteBtn.style.border = "none";
            deleteBtn.style.borderRadius = "4px";
            deleteBtn.style.padding = "4px 8px";
            deleteBtn.style.fontSize = "12px";
            deleteBtn.style.cursor = "pointer";
            deleteBtn.addEventListener("click", () => this.deleteCollection(collection.id));
            collectionActions.appendChild(deleteBtn);
            
            collectionItem.appendChild(collectionInfo);
            collectionItem.appendChild(collectionActions);
            
            collectionsList.appendChild(collectionItem);
        });
    }
    
    // Remove an item from a collection
    removeFromCollection(collectionId, itemUrl) {
        // Get the collections from local storage
        const collections = this.getExistingCollections();
        
        // Find the collection
        const collection = collections.find(c => c.id === collectionId);
        if (!collection) {
            BdApi.showToast(`Collection not found: ${collectionId}`, { type: "error" });
            return;
        }
        
        // Find the item index
        const itemIndex = collection.items.findIndex(item => 
            (typeof item === 'object' ? item.url === itemUrl : item === itemUrl)
        );
        
        if (itemIndex === -1) {
            BdApi.showToast(`Item not found in collection`, { type: "error" });
            return;
        }
        
        // Remove the item
        collection.items.splice(itemIndex, 1);
        
        // Save back to local storage
        this.saveExistingCollections(collections);
        
        // Show success message
        BdApi.showToast(`Item removed from collection`, { type: "success" });
        
        // Re-render the collection view
        this.viewCollection(collection);
    }
    
    // View collection items with safety measures
    viewCollection(collection) {
        const itemCount = collection.items ? collection.items.length : 0;
        
        let content;
        if (itemCount === 0) {
            content = BdApi.React.createElement("p", {
                style: { color: "var(--text-muted)" }
            }, "No items in this collection");
        } else {
            // Create a list of items with appropriate warnings
            content = BdApi.React.createElement("div", null, [
                BdApi.React.createElement("p", {
                    style: { marginBottom: "10px" }
                }, `This collection contains ${itemCount} item${itemCount !== 1 ? 's' : ''}:`),
                BdApi.React.createElement("div", {
                    style: { 
                        maxHeight: "300px", 
                        overflowY: "auto",
                        border: "1px solid var(--background-tertiary)",
                        borderRadius: "4px",
                        padding: "5px"
                    }
                }, collection.items.map(item => {
                    // Determine if this is an object with metadata or just a URL string
                    const itemUrl = typeof item === 'object' ? item.url : item;
                    const itemStatus = typeof item === 'object' ? item.status : 
                        (itemUrl.startsWith('MALWARE-LINK:') ? 'malicious' : 
                         itemUrl.startsWith('SUSPICIOUS-LINK:') ? 'suspicious' : 'unknown');
                    
                    // Get a display version of the URL (with protocols and prefixes removed)
                    let displayUrl = itemUrl;
                    if (itemUrl.startsWith('MALWARE-LINK:')) {
                        displayUrl = itemUrl.replace('MALWARE-LINK:', '').replace(/\[\.\]/g, '.');
                    } else if (itemUrl.startsWith('SUSPICIOUS-LINK:')) {
                        displayUrl = itemUrl.replace('SUSPICIOUS-LINK:', '').replace(/\[\.\]/g, '.');
                    }
                    
                    // For malicious items, add extra warnings
                    const isMalicious = itemStatus === 'malicious';
                    const isSuspicious = itemStatus === 'suspicious';
                    
                    return BdApi.React.createElement("div", {
                        style: {
                            padding: "5px",
                            marginBottom: "5px",
                            borderBottom: "1px solid var(--background-modifier-accent)",
                            wordBreak: "break-all",
                            backgroundColor: isMalicious ? "rgba(240, 71, 71, 0.1)" : 
                                              isSuspicious ? "rgba(250, 166, 26, 0.1)" : "transparent"
                        }
                    }, [
                        // Status badge
                        BdApi.React.createElement("div", {
                            style: {
                                display: "inline-block",
                                padding: "2px 5px",
                                borderRadius: "3px",
                                marginRight: "5px",
                                fontSize: "10px",
                                backgroundColor: isMalicious ? "#f04747" : 
                                                  isSuspicious ? "#faa61a" : "#43b581",
                                color: "white"
                            }
                        }, isMalicious ? "MALICIOUS" : isSuspicious ? "SUSPICIOUS" : "SAFE"),
                        
                        // URL text (not a clickable link for malicious or suspicious)
                        isMalicious || isSuspicious ? 
                            BdApi.React.createElement("span", {
                                style: {
                                    fontWeight: isMalicious ? "bold" : "normal",
                                    color: isMalicious ? "#f04747" : isSuspicious ? "#faa61a" : "inherit"
                                }
                            }, displayUrl) :
                            BdApi.React.createElement("a", {
                                href: displayUrl,
                                target: "_blank",
                                rel: "noopener noreferrer",
                                style: {
                                    color: "var(--text-link)",
                                    textDecoration: "none"
                                }
                            }, displayUrl),
                        
                        // Date added (if available)
                        typeof item === 'object' && item.dateAdded ? 
                            BdApi.React.createElement("div", {
                                style: {
                                    fontSize: "10px",
                                    color: "var(--text-muted)",
                                    marginTop: "2px"
                                }
                            }, `Added: ${new Date(item.dateAdded).toLocaleString()}`) : null,
                        
                        // Remove button
                        BdApi.React.createElement("button", {
                            onClick: () => this.removeFromCollection(collection.id, itemUrl),
                            style: {
                                backgroundColor: "#f04747",
                                color: "white",
                                border: "none",
                                borderRadius: "4px",
                                padding: "2px 5px",
                                fontSize: "10px",
                                marginLeft: "5px",
                                cursor: "pointer",
                                float: "right"
                            }
                        }, "Remove")
                    ]);
                }))
            ]);
        }
        
        BdApi.showConfirmationModal(
            `Collection: ${collection.name}${collection.isLocal ? ' (local)' : ''}`,
            content,
            {
                confirmText: "Close",
                cancelText: null
            }
        );
    }

    // Load existing graphs from local storage
    loadExistingGraphs(graphsList) {
        const existingGraphs = this.getExistingGraphs();
        
        if (existingGraphs.length === 0) {
            const noGraphsMsg = document.createElement("p");
            noGraphsMsg.textContent = "No file graphs created yet";
            noGraphsMsg.className = "vt-empty-list";
            noGraphsMsg.style.padding = "5px";
            noGraphsMsg.style.color = "var(--text-muted)";
            graphsList.appendChild(noGraphsMsg);
            return;
        }

        existingGraphs.forEach(graph => {
            const graphItem = document.createElement("div");
            graphItem.className = "vt-graph-item";
            graphItem.style.display = "flex";
            graphItem.style.justifyContent = "space-between";
            graphItem.style.alignItems = "center";
            graphItem.style.padding = "5px";
            graphItem.style.marginBottom = "5px";
            graphItem.style.borderBottom = "1px solid var(--background-modifier-accent)";
            
            const graphName = document.createElement("span");
            graphName.textContent = graph.name;
            
            const graphActions = document.createElement("div");
            graphActions.className = "vt-graph-actions";

            // Delete button
            const deleteBtn = document.createElement("button");
            deleteBtn.textContent = "Delete";
            deleteBtn.className = "vt-delete-btn";
            deleteBtn.style.backgroundColor = "#f04747";
            deleteBtn.style.color = "white";
            deleteBtn.style.border = "none";
            deleteBtn.style.borderRadius = "4px";
            deleteBtn.style.padding = "4px 8px";
            deleteBtn.style.fontSize = "12px";
            deleteBtn.style.cursor = "pointer";
            deleteBtn.addEventListener("click", () => this.deleteGraph(graph.id));

            graphActions.appendChild(deleteBtn);
            
            graphItem.appendChild(graphName);
            graphItem.appendChild(graphActions);
            
            graphsList.appendChild(graphItem);
        });
    }

    // Get existing collections from local storage
    getExistingCollections() {
        return BdApi.getData("VirusTotalScanner", "collections") || [];
    }

    // Save existing collections to local storage
    saveExistingCollections(collections) {
        BdApi.saveData("VirusTotalScanner", "collections", collections);
    }

    // Get existing graphs from local storage
    getExistingGraphs() {
        return BdApi.getData("VirusTotalScanner", "graphs") || [];
    }

    // Save existing graphs to local storage
    saveExistingGraphs(graphs) {
        BdApi.saveData("VirusTotalScanner", "graphs", graphs);
    }

    // Delete a collection
    deleteCollection(collectionId) {
        BdApi.showConfirmationModal(
            "Delete Collection",
            "Are you sure you want to delete this collection? This will only remove it from the plugin's local storage, not from VirusTotal.",
            {
                danger: true,
                confirmText: "Delete",
                cancelText: "Cancel",
                onConfirm: () => this.performCollectionDeletion(collectionId)
            }
        );
    }
    
    // Actually perform the deletion after confirmation
    performCollectionDeletion(collectionId) {
        // Remove from local storage
        const existingCollections = this.getExistingCollections();
        const updatedCollections = existingCollections.filter(c => c.id !== collectionId);
        this.saveExistingCollections(updatedCollections);

        // Refresh the collections list
        const collectionsList = document.querySelector('.vt-collections-list');
        if (collectionsList) {
            collectionsList.innerHTML = ''; // Clear existing list
            this.loadExistingCollections(collectionsList);
        }

        BdApi.showToast("Collection deleted from local storage", { type: "success" });
    }

    // Delete a graph
    deleteGraph(graphId) {
        BdApi.showConfirmationModal(
            "Delete File Graph",
            "Are you sure you want to delete this file graph? This will only remove it from the plugin's local storage, not from VirusTotal.",
            {
                danger: true,
                confirmText: "Delete",
                cancelText: "Cancel",
                onConfirm: () => this.performGraphDeletion(graphId)
            }
        );
    }
    
    // Actually perform the deletion after confirmation
    performGraphDeletion(graphId) {
        // Remove from local storage
        const existingGraphs = this.getExistingGraphs();
        const updatedGraphs = existingGraphs.filter(g => g.id !== graphId);
        this.saveExistingGraphs(updatedGraphs);

        // Refresh the graphs list
        const graphsList = document.querySelector('.vt-graphs-list');
        if (graphsList) {
            graphsList.innerHTML = ''; // Clear existing list
            this.loadExistingGraphs(graphsList);
        }

        BdApi.showToast("File graph deleted from local storage", { type: "success" });
    }
}

// Main Plugin Class
module.exports = class VirusTotalScanner {
    constructor() {
        this.initialized = false;
        this.enabled = true;
        this.debug = false;
        this.threshold = 5;
        this.requestQueue = [];
        this.requestTimes = []; // Track API request timestamps
        this.processedUrls = new Map(); // Track already processed URLs and their status
        
        // VirusTotal free tier rate limits
        this.RATE_LIMIT = 4; // 4 requests per minute
        this.TIME_WINDOW = 60000; // 60 seconds in milliseconds
        
        // Map to store link-element associations
        this.linkElements = new Map();
        
        // Observer for watching for new links
        this.linkObserver = null;
        
        // List of URL patterns to ignore
        this.ignoredPatterns = [
            // Discord assets and media
            /discord\.com\/assets/,
            /discord\.com\/channels/,
            /media\.discordapp\.net/,
            /cdn\.discordapp\.com\/attachments\/.*\.(png|jpg|jpeg|gif|webp|svg)(\?|$)/i,
            /images-ext.*\.discordapp\.net/,
            // Common image formats
            /\.(png|jpg|jpeg|gif|webp|svg)(\?|$)/i,
            // Discord invite links
            /discord\.gg\//,
            // Local/private IPs
            /^https?:\/\/(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/
        ];
    }

    getName() {
        return "VirusTotalScanner";
    }

    getDescription() {
        return "Scans links in Discord messages using VirusTotal API with collection and graph management";
    }

    getVersion() {
        return "0.5.0";
    }

    getAuthor() {
        return "YourName";
    }

    start() {
        this.log("Starting plugin...");
        
        // Initialize components
        this.settingsExtension = new VirusTotalScannerSettingsExtension(this);
        this.fileTracker = new VirusTotalFileTracker(this);
        
        // Load settings
        this.loadSettings();
        
        if (!this.apiKey) {
            BdApi.showToast("VirusTotal API Key Required", {
                type: "error", 
                timeout: 5000
            });
            BdApi.showConfirmationModal(
                "VirusTotal API Key Required", 
                "Please set your VirusTotal API key in the plugin settings.",
                {
                    confirmText: "Open Settings",
                    cancelText: "Later",
                    onConfirm: () => {
                        BdApi.showConfirmationModal("VirusTotal Scanner Settings", this.getSettingsPanel(), {
                            confirmText: "Save",
                            cancelText: "Cancel"
                        });
                    }
                }
            );
        }
        
        // Initialize observer for links
        this.startLinkObserver();
        
        // Add styles
        this.addStyles();
        
        // Start processing queue
        this.startQueueProcessor();
        
        this.initialized = true;
        this.log("Plugin started");
    }
    
    stop() {
        // Stop the observer
        if (this.linkObserver) {
            this.linkObserver.disconnect();
            this.linkObserver = null;
            // Also clean up the history listeners if we modified them
            if (this._originalPushState) {
                history.pushState = this._originalPushState;
            }
            if (this._originalReplaceState) {
                history.replaceState = this._originalReplaceState;
            }
        }
        
        // Clear the queue interval
        if (this.queueInterval) {
            clearInterval(this.queueInterval);
            this.queueInterval = null;
        }
        
        // Remove styles
        BdApi.clearCSS("vt-scanner-css");
        
        // Clean up any scan buttons
        document.querySelectorAll('.vt-scan-button').forEach(button => {
            button.remove();
        });
        
        this.initialized = false;
        this.log("Plugin stopped");
    }
    
    log(message) {
        if (this.debug || message.startsWith("ERROR:")) {
            console.log(`[VirusTotalScanner] ${message}`);
        }
    }
    
    // Load settings from BdApi
    loadSettings() {
        const settings = BdApi.getData("VirusTotalScanner", "settings") || {};
        this.apiKey = settings.apiKey || "";
        this.enabled = settings.enabled !== undefined ? settings.enabled : true;
        this.debug = settings.debug || false;
        this.threshold = settings.threshold || 5;
    }
    
    // Save settings using BdApi
    saveSettings() {
        BdApi.saveData("VirusTotalScanner", "settings", {
            apiKey: this.apiKey,
            enabled: this.enabled,
            debug: this.debug,
            threshold: this.threshold
        });
    }
    
    // Add CSS styles for the plugin
    addStyles() {
        BdApi.injectCSS("vt-scanner-css", `
            .vt-settings-panel {
                padding: 10px;
            }
            .vt-settings-group {
                margin-bottom: 15px;
            }
            .vt-input {
                width: 100%;
                padding: 8px;
                border-radius: 4px;
                border: 1px solid var(--background-tertiary, #2f3136);
                background: var(--background-secondary, #36393f);
                color: var(--text-normal, #dcddde);
                margin-top: 5px;
            }
            .vt-toggle {
                width: 40px;
                height: 24px;
                background: var(--background-tertiary, #2f3136);
                border-radius: 12px;
                position: relative;
                cursor: pointer;
                margin-top: 5px;
            }
            .vt-toggle:before {
                content: "";
                position: absolute;
                width: 18px;
                height: 18px;
                border-radius: 50%;
                background: var(--interactive-normal, #b9bbbe);
                top: 3px;
                left: 3px;
                transition: transform 0.2s ease;
            }
            .vt-toggle-checked {
                background: var(--brand-experiment, #5865f2);
            }
            .vt-toggle-checked:before {
                transform: translateX(16px);
                background: white;
            }
            .vt-warning-icon {
                color: #f04747;
                margin-right: 4px;
                display: inline-block;
                font-weight: bold;
            }
            .vt-scan-button {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                margin-left: 4px;
                padding: 0 4px;
                height: 18px;
                font-size: 10px;
                font-weight: bold;
                border-radius: 3px;
                color: white;
                background-color: var(--brand-experiment, #5865f2);
                cursor: pointer;
                vertical-align: middle;
                transition: background-color 0.2s ease;
                opacity: 0.8;
            }
            .vt-scan-button:hover {
                opacity: 1;
                background-color: var(--brand-experiment-560, #4752c4);
            }
            .vt-link-scanning {
                text-decoration: underline dotted #faa61a;
            }
            .vt-link-malicious {
                color: #f04747 !important;
                text-decoration: line-through !important;
                background-color: rgba(240, 71, 71, 0.1);
                padding: 0 2px;
                border-radius: 3px;
            }
            .vt-link-suspicious {
                color: #faa61a !important;
                text-decoration: underline wavy #faa61a !important;
            }
            .vt-link-clean {
                color: #43b581 !important;
                text-decoration: underline #43b581 !important;
            }
            .vt-tooltip {
                position: absolute;
                background-color: var(--background-floating, #18191c);
                border-radius: 4px;
                padding: 8px;
                color: var(--text-normal, #dcddde);
                font-size: 14px;
                z-index: 9999;
                box-shadow: 0 2px 10px 0 rgba(0,0,0,.2);
                min-width: 200px;
                max-width: 300px;
            }
            .vt-report-button:hover {
                background-color: var(--brand-experiment-560, #4752c4) !important;
            }
            .vt-dropdown-container {
                margin-top: 8px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                padding-top: 8px;
            }
            .vt-dropdown {
                width: 100%;
                padding: 4px;
                margin-bottom: 5px;
                background-color: var(--background-secondary);
                color: var(--text-normal);
                border: 1px solid var(--background-tertiary);
                border-radius: 4px;
            }
            .vt-collection-item, .vt-graph-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 5px;
                margin-bottom: 5px;
                border-bottom: 1px solid var(--background-modifier-accent);
            }
            .vt-delete-btn {
                background-color: #f04747;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 12px;
                cursor: pointer;
            }
            .vt-add-btn {
                background-color: var(--brand-experiment);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                cursor: pointer;
                margin-bottom: 10px;
            }
            .vt-add-btn:hover {
                background-color: var(--brand-experiment-560);
            }
            .vt-empty-list {
                padding: 5px;
                color: var(--text-muted);
            }
        `);
    }
    
    // Settings panel
    getSettingsPanel() {
        const panel = document.createElement("div");
        panel.className = "vt-settings-panel";
        
        // API Key field
        const apiKeyGroup = document.createElement("div");
        apiKeyGroup.className = "vt-settings-group";
        
        const apiKeyLabel = document.createElement("h3");
        apiKeyLabel.textContent = "VirusTotal API Key";
        
        const apiKeyInput = document.createElement("input");
        apiKeyInput.type = "password";
        apiKeyInput.value = this.apiKey;
        apiKeyInput.placeholder = "Enter your VirusTotal API Key";
        apiKeyInput.className = "vt-input";
        apiKeyInput.addEventListener("input", () => {
            this.apiKey = apiKeyInput.value;
            this.saveSettings();
        });
        
        apiKeyGroup.appendChild(apiKeyLabel);
        apiKeyGroup.appendChild(apiKeyInput);
        
        // Enabled toggle
        const enabledGroup = document.createElement("div");
        enabledGroup.className = "vt-settings-group";
        
        const enabledLabel = document.createElement("h3");
        enabledLabel.textContent = "Enable Scanner";
        
        const enabledToggle = document.createElement("div");
        enabledToggle.className = "vt-toggle";
        enabledToggle.classList.toggle("vt-toggle-checked", this.enabled);
        enabledToggle.addEventListener("click", () => {
            this.enabled = !this.enabled;
            enabledToggle.classList.toggle("vt-toggle-checked", this.enabled);
            this.saveSettings();
            
            if (this.enabled) {
                this.startLinkObserver();
                this.startQueueProcessor();
            } else {
                if (this.linkObserver) {
                    this.linkObserver.disconnect();
                    this.linkObserver = null;
                }
                if (this.queueInterval) {
                    clearInterval(this.queueInterval);
                    this.queueInterval = null;
                }
            }
        });
        
        enabledGroup.appendChild(enabledLabel);
        enabledGroup.appendChild(enabledToggle);
        
        // Debug toggle
        const debugGroup = document.createElement("div");
        debugGroup.className = "vt-settings-group";
        
        const debugLabel = document.createElement("h3");
        debugLabel.textContent = "Debug Mode";
        
        const debugToggle = document.createElement("div");
        debugToggle.className = "vt-toggle";
        debugToggle.classList.toggle("vt-toggle-checked", this.debug);
        debugToggle.addEventListener("click", () => {
            this.debug = !this.debug;
            debugToggle.classList.toggle("vt-toggle-checked", this.debug);
            this.saveSettings();
        });
        
        debugGroup.appendChild(debugLabel);
        debugGroup.appendChild(debugToggle);
        
        // Threshold setting
        const thresholdGroup = document.createElement("div");
        thresholdGroup.className = "vt-settings-group";
        
        const thresholdLabel = document.createElement("h3");
        thresholdLabel.textContent = "Alert Threshold (suspicious engines)";
        
        const thresholdInput = document.createElement("input");
        thresholdInput.type = "number";
        thresholdInput.min = "1";
        thresholdInput.max = "20";
        thresholdInput.value = this.threshold;
        thresholdInput.className = "vt-input";
        thresholdInput.addEventListener("change", () => {
            this.threshold = parseInt(thresholdInput.value) || 5;
            this.saveSettings();
        });
        
        thresholdGroup.appendChild(thresholdLabel);
        thresholdGroup.appendChild(thresholdInput);
        
        // Add all groups to panel
        panel.appendChild(apiKeyGroup);
        panel.appendChild(enabledGroup);
        panel.appendChild(debugGroup);
        panel.appendChild(thresholdGroup);
        
        // Add test button
        const testGroup = document.createElement("div");
        testGroup.className = "vt-settings-group";
        
        const testButton = document.createElement("button");
        testButton.textContent = "Test API Connection";
        testButton.style.padding = "8px 16px";
        testButton.style.backgroundColor = "var(--brand-experiment, #5865f2)";
        testButton.style.color = "white";
        testButton.style.border = "none";
        testButton.style.borderRadius = "4px";
        testButton.style.cursor = "pointer";
        testButton.addEventListener("click", async () => {
            if (!this.apiKey) {
                BdApi.showToast("API key not set", { type: "error" });
                return;
            }
            
            testButton.textContent = "Testing...";
            testButton.disabled = true;
            
            try {
                const result = await this.testApiConnection();
                if (result.success) {
                    BdApi.showToast("API connection successful", { type: "success" });
                } else {
                    BdApi.showToast(`API error: ${result.message}`, { type: "error" });
                }
            } catch (err) {
                BdApi.showToast(`Test failed: ${err.message}`, { type: "error" });
            }
            
            testButton.textContent = "Test API Connection";
            testButton.disabled = false;
        });
        
        testGroup.appendChild(testButton);
        panel.appendChild(testGroup);
        
        // Add collection and graph management
        this.settingsExtension.extendSettingsPanel(panel);
        
        // Add auto-tracking settings
        this.fileTracker.addAutoTrackingSettings(panel);
        
        return panel;
    }
    
    // Test the API connection
    async testApiConnection() {
        try {
            const response = await BdApi.Net.fetch("https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly9nb29nbGUuY29t", {
                method: "GET",
                headers: {
                    "x-apikey": this.apiKey
                }
            });
            
            if (response.status === 401) {
                return { success: false, message: "Invalid API key" };
            }
            
            if (!response.ok) {
                return { success: false, message: `HTTP error ${response.status}` };
            }
            
            return { success: true };
        } catch (err) {
            return { success: false, message: err.message };
        }
    }
    
    // Start link observer
    startLinkObserver() {
        if (!this.enabled || this.linkObserver) return;
        
        // Create a mutation observer to watch for new links
        this.linkObserver = new MutationObserver((mutations) => {
            if (!this.enabled) return;
            
            for (const mutation of mutations) {
                if (mutation.type === "childList" && mutation.addedNodes.length > 0) {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            // Check if this is a link or contains links
                            const links = node.tagName === "A" ? [node] : node.querySelectorAll("a");
                            
                            for (const link of links) {
                                this.addScanButton(link);
                            }
                            
                            // If a chat container or message group is added, this might be a channel switch
                            if (node.classList && (
                                node.classList.contains("chat-3bRxxu") || 
                                node.classList.contains("messages-3amgkR") ||
                                node.classList.contains("messagesWrapper-1sRNjr") ||
                                node.classList.contains("chatContent-3KubbW")
                            )) {
                                this.log("Detected potential channel/server switch, re-processing existing links");
                                setTimeout(() => this.processExistingLinks(), 500);
                            }
                        }
                    }
                }
            }
        });
        
        // Start observing
        this.linkObserver.observe(document.body, { 
            childList: true, 
            subtree: true 
        });
        
        // Also process existing links
        this.processExistingLinks();
        
        // Add a listener for Discord's navigation events
        this.setupNavigationListener();
    }
    
    // Setup navigation listener
    setupNavigationListener() {
        // Store original methods
        this._originalPushState = history.pushState;
        this._originalReplaceState = history.replaceState;
        
        // Override methods
        history.pushState = (...args) => {
            this._originalPushState.apply(history, args);
            this.log("Discord navigation detected (pushState)");
            setTimeout(() => this.processExistingLinks(), 500);
        };
        
        history.replaceState = (...args) => {
            this._originalReplaceState.apply(history, args);
            this.log("Discord navigation detected (replaceState)");
            setTimeout(() => this.processExistingLinks(), 500);
        };
        
        // Also listen for popstate events
        window.addEventListener('popstate', () => {
            this.log("Discord navigation detected (popstate)");
            setTimeout(() => this.processExistingLinks(), 500);
        });
    }

    // Process existing links
    processExistingLinks() {
        const links = document.querySelectorAll("a");
        
        for (const link of links) {
            if (!link.href) continue;
            
            const url = this.sanitizeUrl(link.href);
            
            // Add scan button if needed
            this.addScanButton(link);
            
            // Check if we have already processed this URL
            if (this.processedUrls.has(url)) {
                const status = this.processedUrls.get(url);
                
                // If we have a result (not just "scanning"), restore styling
                if (status !== "scanning" && status !== "error") {
                    // Add this link to the elements map if not already there
                    if (!this.linkElements.has(url)) {
                        this.linkElements.set(url, new Set());
                    }
                    
                    this.linkElements.get(url).add(link);
                    
                    // Update the link styling and add tooltip
                    link.classList.remove("vt-link-scanning", "vt-link-malicious", "vt-link-suspicious", "vt-link-clean");
                    link.classList.add(`vt-link-${status}`);
                    
                    // Re-add tooltip if needed
                    // We need to get the scan result data
                    try {
                        // We'll create a minimal scan result with the info we have
                        const minimalScanResult = {
                            url: url,
                            lastScan: Date.now() / 1000, // Current time as timestamp
                            vtLink: `https://www.virustotal.com/gui/url/${btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}/detection`,
                            malicious: 0,
                            suspicious: 0,
                            harmless: 0,
                            totalEngines: 0,
                            engines: { malicious: [], suspicious: [] }
                        };
                        
                        // Set appropriate values based on status
                        if (status === "malicious") {
                            minimalScanResult.malicious = 1; // At least 1 detection
                            minimalScanResult.totalEngines = 1;
                        } else if (status === "suspicious") {
                            minimalScanResult.suspicious = this.threshold;
                            minimalScanResult.totalEngines = this.threshold;
                        } else {
                            minimalScanResult.harmless = 1;
                            minimalScanResult.totalEngines = 1;
                        }
                        
                        this.addTooltip(link, minimalScanResult);
                    } catch (e) {
                        this.log(`ERROR: Failed to restore tooltip: ${e.message}`);
                    }
                }
            }
        }
    }
    
    // Should the URL be ignored?
    shouldIgnoreUrl(url) {
        // Check if URL matches any of our ignored patterns
        for (const pattern of this.ignoredPatterns) {
            if (pattern.test(url)) {
                return true;
            }
        }
        
        return false;
    }
    
    // Sanitize URL for VirusTotal submission
    sanitizeUrl(url) {
        // For Discord CDN links, remove the query parameters which can cause issues
        if (url.includes('cdn.discordapp.com/attachments/')) {
            const urlObj = new URL(url);
            // Remove Discord CDN query parameters
            urlObj.search = '';
            return urlObj.toString();
        }
        
        // For other URLs, return as is
        return url;
    }
    
    // Add a scan button next to a link
    addScanButton(linkElement) {
        if (!linkElement || !linkElement.href) return;
        
        let url = linkElement.href;
        
        // Skip internal Discord links and ignored patterns
        if (this.shouldIgnoreUrl(url)) {
            this.log(`Ignoring URL: ${url}`);
            return;
        }
        
        // Check if this link already has a scan button
        if (linkElement.nextSibling && linkElement.nextSibling.classList && 
            linkElement.nextSibling.classList.contains('vt-scan-button')) {
            return;
        }
        
        // Sanitize URL for VirusTotal submission
        const sanitizedUrl = this.sanitizeUrl(url);
        
        // Create scan button
        const scanButton = document.createElement('span');
        scanButton.className = 'vt-scan-button';
        scanButton.textContent = 'Scan';
        scanButton.title = 'Scan with VirusTotal';
        
        // Check if we already have results for this URL
        if (this.processedUrls.has(sanitizedUrl)) {
            const status = this.processedUrls.get(sanitizedUrl);
            scanButton.textContent = this.getScanButtonText(status);
            scanButton.style.backgroundColor = this.getScanButtonColor(status);
        }
        
        // Add click handler
        scanButton.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            // If URL is already processed, show results
            if (this.processedUrls.has(sanitizedUrl)) {
                const status = this.processedUrls.get(sanitizedUrl);
                
                // If it's an actual result (not "scanning"), update the UI
                if (status !== 'scanning') {
                    this.updateLinkElements(sanitizedUrl, status);
                }
                return;
            }
            
            // Otherwise, process the link
            this.processLink(linkElement, sanitizedUrl);
            
            // Update button to show scanning
            scanButton.textContent = 'Scanning...';
            scanButton.style.backgroundColor = '#7289da';
        });
        
        // Insert after the link
        if (linkElement.parentNode) {
            linkElement.parentNode.insertBefore(scanButton, linkElement.nextSibling);
        }
    }
    
    // Get appropriate text for scan button based on status
    getScanButtonText(status) {
        switch(status) {
            case 'malicious': return 'Malicious';
            case 'suspicious': return 'Suspicious';
            case 'clean': return 'Clean';
            case 'scanning': return 'Scanning...';
            case 'error': return 'Error';
            default: return 'Scan';
        }
    }
    
    // Get appropriate color for scan button based on status
    getScanButtonColor(status) {
        switch(status) {
            case 'malicious': return '#f04747';
            case 'suspicious': return '#faa61a';
            case 'clean': return '#43b581';
            case 'scanning': return '#7289da';
            case 'error': return '#747f8d';
            default: return 'var(--brand-experiment, #5865f2)';
        }
    }
    
    // Process a link element
    processLink(linkElement, sanitizedUrl) {
        if (!linkElement || !sanitizedUrl) return;
        
        // Associate this element with the URL for later update
        if (!this.linkElements.has(sanitizedUrl)) {
            this.linkElements.set(sanitizedUrl, new Set());
        }
        this.linkElements.get(sanitizedUrl).add(linkElement);
        
        // Mark URL as being processed
        this.processedUrls.set(sanitizedUrl, 'scanning');
        
        // Add scanning indicator
        linkElement.classList.add("vt-link-scanning");
        
        // Queue this URL for scanning
        this.queueForScanning(sanitizedUrl);
    }
    
    // Queue a URL for scanning
    queueForScanning(url) {
        if (!this.enabled || !this.apiKey) return;
        
        // Add to queue if not already there
        if (!this.requestQueue.includes(url)) {
            this.requestQueue.push(url);
            this.log(`Queued for scanning: ${url}`);
        }
    }
    
    // Start the queue processor
    startQueueProcessor() {
        if (this.queueInterval) {
            clearInterval(this.queueInterval);
        }
        
        this.queueInterval = setInterval(() => {
            this.processNextInQueue();
        }, 15000); // Process a URL every 15 seconds to respect rate limits
    }
    
    // Process the next URL in the queue
    async processNextInQueue() {
        if (!this.enabled || !this.apiKey || this.requestQueue.length === 0) {
            return;
        }
        
        // Check rate limit
        if (this.isRateLimited()) {
            this.log("Rate limited, waiting...");
            return;
        }
        
        const url = this.requestQueue.shift();
        this.log(`Processing URL: ${url}`);
        
        try {
            await this.scanWithVirusTotal(url);
            
            // Track API request time for rate limiting
            this.requestTimes.push(Date.now());
        } catch (err) {
            this.log(`ERROR: Failed to scan URL: ${err.message}`);
            
            // Update UI to show error
            this.processedUrls.set(url, 'error');
            this.updateLinkElements(url, "error");
        }
    }
    
    // Check if rate limited
    isRateLimited() {
        const now = Date.now();
        
        // Remove timestamps older than the time window
        this.requestTimes = this.requestTimes.filter(time => now - time < this.TIME_WINDOW);
        
        // Check if we're within the rate limit
        return this.requestTimes.length >= this.RATE_LIMIT;
    }
    
    // Scan a URL with VirusTotal
    async scanWithVirusTotal(url) {
        if (!this.apiKey) {
            this.log("ERROR: API key not set");
            return;
        }
        
        try {
            // Encode the URL for the API request
            const encodedUrl = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            
            // Check if the URL has already been analyzed
            const response = await BdApi.Net.fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
                method: 'GET',
                headers: {
                    'x-apikey': this.apiKey
                }
            });
            
            if (response.status === 404) {
                // URL not found, submit it for analysis
                this.log(`URL not analyzed before, submitting: ${url}`);
                await this.submitUrlForAnalysis(url);
                
                // Re-queue for scanning after a delay
                setTimeout(() => {
                    this.queueForScanning(url);
                }, 30000); // 30 second delay
                
                return;
            }
            
            if (!response.ok) {
                throw new Error(`API request failed with status ${response.status}`);
            }
            
            const data = await response.json();
            this.processVirusTotalResults(url, data);
            
        } catch (err) {
            this.log(`ERROR: Scan failed: ${err.message}`);
            this.processedUrls.set(url, 'error');
            this.updateLinkElements(url, "error");
            throw err;
        }
    }
    
    // Submit a URL for analysis
    async submitUrlForAnalysis(url) {
        try {
            // Use URLSearchParams instead of FormData as it works better with BdApi.Net.fetch
            const urlParams = new URLSearchParams();
            urlParams.append('url', url);
            
            const response = await BdApi.Net.fetch('https://www.virustotal.com/api/v3/urls', {
                method: 'POST',
                headers: {
                    'x-apikey': this.apiKey,
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: urlParams.toString()
            });
            
            if (!response.ok) {
                throw new Error(`URL submission failed with status ${response.status}`);
            }
            
            this.log(`URL submitted for analysis: ${url}`);
            
        } catch (err) {
            this.log(`ERROR: URL submission failed: ${err.message}`);
            this.processedUrls.set(url, 'error');
            this.updateLinkElements(url, "error");
            throw err;
        }
    }
    
    // Process VirusTotal results
    processVirusTotalResults(url, data) {
        if (!data || !data.data || !data.data.attributes || !data.data.attributes.last_analysis_results) {
            this.log("ERROR: Invalid response data");
            this.processedUrls.set(url, 'error');
            this.updateLinkElements(url, "error");
            return;
        }
        
        const results = data.data.attributes.last_analysis_results;
        const stats = data.data.attributes.last_analysis_stats;
        
        // Calculate totals
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const harmless = stats.harmless || 0;
        const totalEngines = Object.keys(results).length;
        
        this.log(`Results for ${url}: Malicious=${malicious}, Suspicious=${suspicious}, Clean=${harmless}, Total=${totalEngines}`);
        
        // Store results for this URL
        const scanResult = {
            url,
            malicious,
            suspicious,
            harmless,
            totalEngines,
            engines: {
                malicious: Object.entries(results)
                    .filter(([_, result]) => result.category === 'malicious')
                    .map(([engine, _]) => engine),
                suspicious: Object.entries(results)
                    .filter(([_, result]) => result.category === 'suspicious')
                    .map(([engine, _]) => engine)
            },
            lastScan: data.data.attributes.last_analysis_date,
            vtLink: `https://www.virustotal.com/gui/url/${btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}/detection`
        };
        
        // Update status based on results
        let status;
        if (malicious > 0) {
            status = "malicious";
        } else if (suspicious >= this.threshold) {
            status = "suspicious";
        } else {
            status = "clean";
        }
        
        // Store the status for this URL
        this.processedUrls.set(url, status);
        
        // Update UI based on results
        this.updateLinkElements(url, status, scanResult);
        
        // Process file for tracking if malicious or suspicious
        if (status === "malicious" || status === "suspicious") {
            try {
                if (this.fileTracker) {
                    this.log(`Processing file for tracking: ${url}`);
                    this.fileTracker.processFile(url, scanResult);
                } else {
                    this.log("ERROR: fileTracker is not initialized");
                }
            } catch (error) {
                this.log(`ERROR: Failed to process file for tracking: ${error.message}`);
            }
        }
    }
    
    // Update all link elements and scan buttons associated with a URL
    updateLinkElements(url, status, scanResult = null) {
        const elements = this.linkElements.get(url);
        if (!elements || elements.size === 0) return;
        
        // Process each element
        for (const element of elements) {
            if (!element || !document.body.contains(element)) {
                // Element was removed from DOM
                elements.delete(element);
                continue;
            }
            
            // Remove scanning class
            element.classList.remove("vt-link-scanning");
            
            // Remove existing status classes
            element.classList.remove("vt-link-malicious", "vt-link-suspicious", "vt-link-clean");
            
            // Update status
            switch (status) {
                case "malicious":
                    element.classList.add("vt-link-malicious");
                    // Add tooltip for details
                    this.addTooltip(element, scanResult);
                    break;
                    
                case "suspicious":
                    element.classList.add("vt-link-suspicious");
                    // Add tooltip for details
                    this.addTooltip(element, scanResult);
                    break;
                    
                case "clean":
                    element.classList.add("vt-link-clean");
                    // Add tooltip for details
                    this.addTooltip(element, scanResult);
                    break;
                    
                case "error":
                case "scanning":
                    // Clear any classes
                    break;
            }
            
            // Update scan button if it exists
            const scanButton = element.nextSibling;
            if (scanButton && scanButton.classList && scanButton.classList.contains('vt-scan-button')) {
                scanButton.textContent = this.getScanButtonText(status);
                scanButton.style.backgroundColor = this.getScanButtonColor(status);
                
                // For malicious URLs, also show notification
                if (status === "malicious" && scanResult) {
                    this.showMaliciousNotification(url, scanResult);
                }
            }
        }
    }
    
    // Add tooltip with detailed information
    addTooltip(element, scanResult) {
        if (!scanResult) return;
        
        // Clean up any existing tooltip events
        if (element._vtTooltipListeners) {
            element.removeEventListener("mouseenter", element._vtTooltipListeners.enter);
            element.removeEventListener("mouseleave", element._vtTooltipListeners.leave);
            element._vtTooltipListeners = null;
        }
        
        // Debug logging
        this.log(`Adding tooltip for URL: ${scanResult.url}`);
        
        // Add hover events for tooltip
        const enterListener = (e) => {
            // Remove any existing tooltip
            if (document.querySelector('.vt-tooltip')) {
                document.querySelector('.vt-tooltip').remove();
            }
            
            // Create tooltip
            const tooltip = document.createElement("div");
            tooltip.className = "vt-tooltip";
            
            // Create content
            let content = "";
            
            if (scanResult.malicious > 0) {
                content += `<div style="color: #f04747; font-weight: bold;">⚠️ Malicious: ${scanResult.malicious}/${scanResult.totalEngines}</div>`;
            }
            
            if (scanResult.suspicious > 0) {
                content += `<div style="color: #faa61a; font-weight: bold;">⚠️ Suspicious: ${scanResult.suspicious}/${scanResult.totalEngines}</div>`;
            }
            
            if (scanResult.malicious === 0 && scanResult.suspicious < this.threshold) {
                content += `<div style="color: #43b581; font-weight: bold;">✓ Clean: ${scanResult.harmless}/${scanResult.totalEngines}</div>`;
            }
            
            content += `<div style="margin-top: 4px;">Scan date: ${new Date(scanResult.lastScan * 1000).toLocaleString()}</div>`;
            
            if (scanResult.engines.malicious.length > 0) {
                content += `<div style="margin-top: 4px; font-size: 12px;">Malicious engines: ${scanResult.engines.malicious.join(", ")}</div>`;
            }
            
            if (scanResult.engines.suspicious.length > 0) {
                content += `<div style="margin-top: 4px; font-size: 12px;">Suspicious engines: ${scanResult.engines.suspicious.join(", ")}</div>`;
            }
            
            // Add the view report button instead of a link
            content += `<div style="margin-top: 6px; text-align: center;">
                <button class="vt-report-button" style="
                    background-color: var(--brand-experiment, #5865f2);
                    color: white;
                    border: none;
                    border-radius: 3px;
                    padding: 5px 10px;
                    font-size: 12px;
                    cursor: pointer;
                    width: 100%;
                ">View full report on VirusTotal</button>
            </div>`;
            
            tooltip.innerHTML = content;
            
            // Add click event to button
            setTimeout(() => {
                const reportButton = tooltip.querySelector('.vt-report-button');
                if (reportButton) {
                    reportButton.addEventListener('click', (e) => {
                        e.stopPropagation();
                        window.open(scanResult.vtLink, '_blank');
                    });
                }
            }, 0);
            
            // Position the tooltip - make sure it's visible in viewport
            const rect = element.getBoundingClientRect();
            const viewportHeight = window.innerHeight;
            
            // Default position below the element
            let top = rect.bottom + 8;
            
            // If there's not enough space below, put it above
            if (top + 150 > viewportHeight) { // Approximate tooltip height
                top = rect.top - 150 - 8; // Place above with margin
            }
            
            // If it would be off-screen at the top too, place it at the top of viewport
            if (top < 10) {
                top = 10;
            }
            
            tooltip.style.left = `${rect.left}px`;
            tooltip.style.top = `${top}px`;
            tooltip.style.maxHeight = "300px";
            tooltip.style.overflowY = "auto";
            
            // Add to DOM
            document.body.appendChild(tooltip);
            
            // Keep tooltip visible when hovering over it
            tooltip.addEventListener('mouseenter', () => {
                if (element._tooltipLeaveTimeout) {
                    clearTimeout(element._tooltipLeaveTimeout);
                    element._tooltipLeaveTimeout = null;
                }
            });
            
            tooltip.addEventListener('mouseleave', () => {
                element._tooltipLeaveTimeout = setTimeout(() => {
                    if (tooltip && document.body.contains(tooltip)) {
                        tooltip.remove();
                    }
                }, 300);
            });
            
            // Store for removal
            element._vtTooltip = tooltip;
            
            // Add collection/graph options to tooltip if applicable
            // Debug log to trace tooltip modification
            this.log(`Modifying tooltip for URL: ${scanResult.url}`);
            try {
                if (this.fileTracker) {
                    this.fileTracker.modifyTooltip(tooltip, scanResult.url, scanResult);
                } else {
                    this.log("ERROR: fileTracker is not initialized");
                }
            } catch (error) {
                this.log(`ERROR: Failed to modify tooltip: ${error.message}`);
            }
        };
        
        const leaveListener = () => {
            // Use a timeout to allow moving to the tooltip itself
            element._tooltipLeaveTimeout = setTimeout(() => {
                if (element._vtTooltip && document.body.contains(element._vtTooltip)) {
                    element._vtTooltip.remove();
                    element._vtTooltip = null;
                }
            }, 300);
        };
        
        element.addEventListener("mouseenter", enterListener);
        element.addEventListener("mouseleave", leaveListener);
        
        // Store listeners for cleanup
        element._vtTooltipListeners = {
            enter: enterListener,
            leave: leaveListener
        };
    }

    // Show notification for malicious links
    showMaliciousNotification(url, scanResult) {
        if (!scanResult) return;
        
        BdApi.showToast(`Malicious link detected! (${scanResult.malicious}/${scanResult.totalEngines})`, {
            type: "danger",
            timeout: 5000
        });
    }
};
