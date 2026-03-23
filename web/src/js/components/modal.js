/**
 * Modal component — styles and behaviors.
 */

// Add modal styles dynamically
const modalStyles = document.createElement('style');
modalStyles.textContent = `
    .modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
        padding: 2rem;
        animation: fadeIn 0.2s ease;
    }

    .modal-content {
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        width: 100%;
        max-width: 800px;
        max-height: 85vh;
        overflow-y: auto;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
    }

    .modal-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1.25rem 1.5rem;
        border-bottom: 1px solid var(--border);
        position: sticky;
        top: 0;
        background: var(--card-bg);
        z-index: 1;
    }

    .modal-header h3 {
        font-size: 1.1rem;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    #modal-body {
        padding: 1.5rem;
    }

    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
`;
document.head.appendChild(modalStyles);

// Close modal on overlay click
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) {
        e.target.style.display = 'none';
    }
});

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay').forEach(m => m.style.display = 'none');
    }
});
