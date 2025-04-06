

    /*
    ==================================
    |
    |   Global 
    |
    ===================================
    */ 
    let cy;
    
    function hideTooltip() {
        tooltip.style.display = 'none';
        isTooltipVisible = false;
    }

    function deselectNode(nodeId) {
        const checkbox = document.getElementById(`checkbox-${nodeId}`);
        if (checkbox) {
        checkbox.checked = false;
        const node = cy.getElementById(nodeId); 
        node.style('display', 'none');
        }

        cy.nodes(`[type="domain"], [type="ip"]`).forEach((targetNode) => {
        const connectedProcesses = targetNode.connectedEdges().connectedNodes('[type="process"]');
        const isVisible = connectedProcesses.some((processNode) => processNode.style('display') !== 'none');
        if (!isVisible) {
            targetNode.style('display', 'none');
        }
        });
        hideTooltip();
    }

    fetch('data.json')
    .then(response => response.json())
    .then(data => {
        cy = cytoscape({
        container: document.getElementById('cy'),
        elements: data.elements,
        layout: { 
            name: 'cose',
            animate: false,
            nodeRepulsion: 250000,
            randomize: true
        },
        style: [
            {
            selector: 'node[type = "process"]',
            style: {
                'shape': 'data(shape)',         
                'border-width': 2,     
                'border-color': '#000000',     
                'border-style': 'solid',
                'background-color': 'data(color)',  
                'label': 'data(label)',
                'text-valign': 'center',       
                'text-halign': 'right',         
                'text-margin-x': 5,            
                'text-margin-y': 0, 
                'width': 'data(width)',
                'height': 'data(height)'
            },
            },
            {
            selector: 'node[type = "domain"]',
            style: {
                'shape': 'data(shape)',         
                'border-width': 2,              
                'border-color': '#000000',      
                'border-style': 'solid',
                'background-color': 'data(color)', 
                'label': 'data(label)',
                'text-valign': 'center',        
                'text-halign': 'right',         
                'text-margin-x': 5,             
                'text-margin-y': 0, 
                'width': 'data(width)',
                'height': 'data(height)'
            },
            },
            {
            selector: 'node[type = "ip"]',
            style: {
                'shape': 'data(shape)',         
                'border-width': 2,             
                'border-color': '#000000',     
                'border-style': 'solid',
                'background-color': 'data(color)', 
                'label': 'data(label)',
                'text-valign': 'center',       
                'text-halign': 'right',         
                'text-margin-x': 5,             
                'text-margin-y': 0,
                'width': 'data(width)',
                'height': 'data(height)'
            },
            },
            {
            selector: 'edge[type = "processStart"]',
            style: {
                'width': 2, 
                'curve-style': 'bezier',
                'line-color': '#000000', 
                'target-arrow-color': '#000000', 
                'target-arrow-shape': 'triangle',
                'label': '', 
            },
            },
            {
            selector: 'edge[type = "dnsQuery"]',
            style: {
                'width': 1, 
                'curve-style': 'bezier', 
                'line-color': '#9e9e9e',
                'line-style': 'dotted', 
                'target-arrow-color': '#9e9e9e', 
                'target-arrow-shape': 'triangle',
                'label': '', 
            },
            },
            {
            selector: 'edge[type = "dnsResolution"]',
            style: {

                'width': 1, 
                'curve-style': 'bezier', 
                'line-color': '#9e9e9e', 
                'line-style': 'dotted', 
                'target-arrow-color': '#9e9e9e', 
                'target-arrow-shape': 'triangle',
                'label': '',
            },
            },
            {
            selector: 'edge[type = "tcpipConnection"]',
            style: {
                'width': 1,  
                'curve-style': 'bezier', 
                'line-color': '#9e9e9e',
                'line-style': 'dotted', 
                'target-arrow-color': '#9e9e9e',
                'target-arrow-shape': 'triangle',
                'label': '',
            },
            },
            {
            selector: 'node.highlighted',
            style: {
                'border-width': 4, 
                'width': '65',
                'height': '65',
                'transition-property': 'width height font-size font-weight', 
                'transition-duration': '0.3s', 
                'transition-timing-function': 'ease',
                'font-weight': 'bold',
                'font-size': '22px',
                'text-opacity': 1,
                'z-index': 9999       
            }
            }
        ],
        
        });
        /*
        ==================================
        |
        |   Metadata management 
        |
        ===================================
        */ 
        const metadataPane = document.getElementById("metadata-pane");
        const metadataLabel = document.getElementById("metadata-label");
    
        metadataPane.innerHTML = ''; 

        if (data.metadata) {
        
            const keyMap = {
                "WYCVersion": "Version",
                "WYCCommandline": "Commandline",
                "Hostname": "Hostname",
                "StartTime": "Started",
                "PresentableDuration": "Duration"
            };
        
            for (const key in keyMap) {
                if (data.metadata[key]) {
                    const p = document.createElement("p");
                    p.innerHTML = `<b>${keyMap[key]}</b>: ${data.metadata[key]}`;
                    metadataPane.appendChild(p);
                }
            }
            
            if (data.metadata["NumberOfProcesses"] && data.metadata["NumberOfProcessesWithNetworkActivity"]) {
                const p = document.createElement("p");
                p.innerHTML = `${data.metadata["NumberOfProcessesWithNetworkActivity"]}/${data.metadata["NumberOfProcesses"]} processes had recorded TCPIP/DNS activity`;
                metadataPane.appendChild(p);
            }

        }else{
            const p = document.createElement("p");
            p.innerHTML = `Nothing to display`;
            metadataPane.appendChild(p);
        }
        metadataLabel.addEventListener("click", () => {
            metadataPane.classList.toggle("open");
        });
    
        metadataPane.addEventListener("click", () => {
            metadataPane.classList.toggle("open");
        });
    
        /*
        ==================================
        |
        |   Checkbox management 
        |
        ===================================
        */ 
        const checkboxPane = document.getElementById('checkbox-list');

        const selectAllCheckbox = document.createElement('input');
        selectAllCheckbox.type = 'checkbox';
        selectAllCheckbox.id = 'checkbox-select-all';
        selectAllCheckbox.checked = true;

        const selectAllLabel = document.createElement('label');
        selectAllLabel.htmlFor = 'checkbox-select-all';
        selectAllLabel.id = 'label-select-all'
        selectAllLabel.textContent = 'Every process';

        selectAllCheckbox.addEventListener('change', () => {
        const isChecked = selectAllCheckbox.checked;

        hideOrphanedCheckbox.checked = isChecked;
        checkboxes.forEach(({ node, checkbox }) => {
            checkbox.checked = isChecked;
            toggleNodeVisibility(node, isChecked);
        });

        updateTargetNodeVisibility();
        hideTooltip();
        cy.nodes().removeClass('highlighted'); 
        });

        const selectAllContainer = document.createElement('div');
        selectAllContainer.appendChild(selectAllCheckbox);
        selectAllContainer.appendChild(selectAllLabel);

        /*
        ==================================
        |
        |   Checkbox management - Processes without network activity
        |
        ===================================
        */ 

        const hideOrphanedCheckbox = document.createElement('input');
        hideOrphanedCheckbox.type = 'checkbox';
        hideOrphanedCheckbox.id = 'checkbox-hide-orphaned';
        hideOrphanedCheckbox.checked = true; 

        const hideOrphanedLabel = document.createElement('label');
        hideOrphanedLabel.id = 'label-hide-orphaned'
        hideOrphanedLabel.htmlFor = 'checkbox-hide-orphaned';
        hideOrphanedLabel.textContent = 'Processes without DNS or TCPIP activity';

        const hideOrphanedContainer = document.createElement('div');
        hideOrphanedContainer.id = 'container-hide-orphaned';
        hideOrphanedContainer.appendChild(hideOrphanedCheckbox);
        hideOrphanedContainer.appendChild(hideOrphanedLabel);

        checkboxPane.insertBefore(hideOrphanedContainer, checkboxPane.firstChild);

        hideOrphanedCheckbox.addEventListener('change', () => {
        const isChecked = hideOrphanedCheckbox.checked;

        processNodes.forEach((node) => {
            const hasTargetEdges = node.connectedEdges().some((edge) => {
            const targetNode = edge.target();
            return targetNode.data('type') === 'domain' || targetNode.data('type') === 'ip';
            });

            const orphanedNodeId = node.data('id');
            if (!hasTargetEdges) {
            toggleNodeVisibility(node, isChecked); 
            const checkbox = document.getElementById(`checkbox-${orphanedNodeId}`);
            checkbox.checked = isChecked;
            }
        });

        updateTargetNodeVisibility();
    });

        checkboxPane.appendChild(hideOrphanedContainer);
        checkboxPane.appendChild(selectAllContainer);

        const processNodes = cy.nodes()
        .filter(node => node.data('type') === 'process')
        .sort((a, b) => a.data('label').localeCompare(b.data('label')));

        const checkboxes = [];

        processNodes.forEach((node) => {
        const nodeLabel = node.data('label');

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.id = `checkbox-${node.id()}`;
        checkbox.checked = true;

        checkbox.addEventListener('change', () => {
            toggleNodeVisibility(node, checkbox.checked);
            updateTargetNodeVisibility();

            const allChecked = checkboxes.every(({ checkbox }) => checkbox.checked);
            const noneChecked = checkboxes.every(({ checkbox }) => !checkbox.checked);
            selectAllCheckbox.checked = allChecked;
            hideOrphanedCheckbox.checked = allChecked;
            selectAllCheckbox.indeterminate = !allChecked && !noneChecked;
        });

        const label = document.createElement('label');
        label.htmlFor = `checkbox-${node.id()}`;
        label.textContent = nodeLabel;

        const container = document.createElement('div');
        container.appendChild(checkbox);
        container.appendChild(label);

        checkboxPane.appendChild(container);

        checkboxes.push({ node, checkbox });
        });

        function toggleNodeVisibility(node, isVisible) {
        node.style('display', isVisible ? 'element' : 'none');
        }

        function updateTargetNodeVisibility() {
        cy.nodes().forEach((targetNode) => {
            const targetType = targetNode.data('type');
            if (targetType === 'domain' || targetType === 'ip') {
            const connectedProcesses = targetNode.connectedEdges().filter(edge => {
                const sourceNode = edge.source();
                return sourceNode.data('type') === 'process' && sourceNode.style('display') !== 'none';
            });

            if (connectedProcesses.length === 0) {
                targetNode.style('display', 'none');
            } else {
                targetNode.style('display', 'element');
            }
            }
        });
        }

    /*
    ==================================
    |
    |   Tooltip management
    |
    ===================================
    */        
        const tooltip = document.getElementById('tooltip');
        let isTooltipVisible = false;

        cy.on('click', 'node', function(event) {
        cy.nodes().removeClass('highlighted'); 
        const node = event.target;
        const position = node.renderedPosition();
        const tooltipText = node.data('info'); 
        const nodeId = node.data('id');
        const nodeType = node.data('type');

        tooltip.innerHTML = tooltipText;
        tooltip.style.display = 'block';
        isTooltipVisible = true;
        node.addClass('highlighted');
        });

        cy.on('click', 'edge', function(event) {
        const edge = event.target;
        const edgeLabel = edge.data('info'); 

        edge.data('label', edgeLabel);

        cy.style()
            .selector('edge')
            .style({
                'label': 'data(label)', 
                'text-opacity': 1,
                'font-size': 10,
                'text-valign': 'center',
                'color': '#000',
                'text-background-color': '#fff', 
                'text-background-opacity': 1,
                'text-background-shape': 'round-rectangle', 
                'text-background-padding': '2px' 
            })
            .update();
    });

    cy.on('click', function (event) {
        if (event.target === cy) {
        hideTooltip(); 
        cy.elements('.highlighted').removeClass('highlighted');
        cy.edges().forEach(edge => {
            edge.data('label', ''); 
        });

        cy.style()
            .selector('edge[label]') 
            .style({
                'label': 'data(label)', 
                'text-opacity': 1,
                'font-size': 10,
                'text-valign': 'center',
                'color': '#000',
            })
            .update();
        }
    });
    
    })
    .catch(error => console.error('Error loading data:', error));