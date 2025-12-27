
/*
=================================================== TAB MANAGEMENT ===================================================
*/
const tabs = document.querySelectorAll('.tab');
const views = document.querySelectorAll('.view');

tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        // Remove active states
        tabs.forEach(t => t.classList.remove('active'));
        views.forEach(v => v.classList.remove('active'));

        // Activate selected
        tab.classList.add('active');
        document.getElementById(tab.dataset.view).classList.add('active');
    });
});