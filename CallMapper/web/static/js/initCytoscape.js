import { loadCallMapperData } from './dataLoader.js';

/*
==================================
|
|   Global 
|
===================================
*/ 
let cy = null;

export function getCy() {
  if (!cy) {
    throw new Error('Cytoscape not initialized yet');
  }
  return cy;
}

async function initCytoscape() {
    const data = await loadCallMapperData();

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
    |   Zooming - To end up on a non-bad zoom value that causes jitter
    |
    ===================================
    */   

    cy.on('zoom', () => {
        const z = cy.zoom();
        const snapped = Math.round(z * 8) / 8; 
        if (Math.abs(z - snapped) > 0.001) {
            cy.zoom(snapped);
        }
    });



    /*
    ==================================
    |
    |   Panning
    |
    ===================================
    */     
    let isPanning = false;

    cy.on('panstart', () => isPanning = true);
    cy.on('panend', () => isPanning = false);

    /*
    ==================================
    |
    |   Tooltip management
    |
    ===================================
    */        

    function hideTooltip() {
        tooltip.style.display = 'none';
        isTooltipVisible = false;
    }

    const tooltip = document.getElementById('tooltip');
    let isTooltipVisible = false;

    cy.on('click', 'node', function(event) {
        if (isPanning) return;
        cy.nodes().removeClass('highlighted'); 
        const node = event.target;
        const position = node.renderedPosition();
        const tooltipText = node.data('info'); 
        const nodeId = node.data('id');
        const nodeType = node.data('type');


        // DEBUGGING £££ 
        const nodeData = node.data();

        const jsonString = JSON.stringify(nodeData, null, 2);

        tooltip.innerHTML = `<pre>${jsonString}</pre>`;

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
}

initCytoscape();