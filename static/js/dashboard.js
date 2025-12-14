// Dashboard JavaScript

document.addEventListener('DOMContentLoaded', function() {
    console.log('TEGEN-CLOUD Dashboard loaded');
    
    // Panic Mode Modal
    const panicBtn = document.getElementById('panicBtn');
    const panicModal = document.getElementById('panicModal');
    const closeModal = document.querySelector('.close-modal');
    const cancelPanic = document.getElementById('cancelPanic');
    const confirmPanic = document.getElementById('confirmPanic');
    
    if (panicBtn && panicModal) {
        panicBtn.addEventListener('click', function() {
            panicModal.classList.add('active');
            document.body.style.overflow = 'hidden';
        });
        
        function closePanicModal() {
            panicModal.classList.remove('active');
            document.body.style.overflow = '';
        }
        
        if (closeModal) closeModal.addEventListener('click', closePanicModal);
        if (cancelPanic) cancelPanic.addEventListener('click', closePanicModal);
        
        // Close modal on outside click
        panicModal.addEventListener('click', function(e) {
            if (e.target === panicModal) {
                closePanicModal();
            }
        });
        
        // Confirm panic mode
        if (confirmPanic) {
            confirmPanic.addEventListener('click', function() {
                const recoveryInput = document.getElementById('panicRecovery');
                if (!recoveryInput || !recoveryInput.value.trim()) {
                    alert('Please enter your recovery phrase to confirm');
                    return;
                }
                
                // In production, this would make an API call
                alert('Panic mode would be activated here. Redirecting to disguised interface...');
                closePanicModal();
                
                // Simulate redirect
                setTimeout(() => {
                    window.location.href = '/panic';
                }, 1000);
            });
        }
    }
    
    // Navigation highlighting
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            if (this.getAttribute('href').startsWith('#')) {
                e.preventDefault();
                navLinks.forEach(l => l.classList.remove('active'));
                this.classList.add('active');
                
                // Scroll to section
                const targetId = this.getAttribute('href');
                const targetSection = document.querySelector(targetId);
                if (targetSection) {
                    targetSection.scrollIntoView({ behavior: 'smooth' });
                }
            }
        });
    });
    
    // Simulate live updates for integrity chain
    function animateIntegrityChain() {
        const ledgerBlocks = document.querySelectorAll('.ledger-block');
        ledgerBlocks.forEach((block, index) => {
            setTimeout(() => {
                block.style.transform = 'scale(1.05)';
                block.style.transition = 'transform 0.3s ease';
                
                setTimeout(() => {
                    block.style.transform = 'scale(1)';
                }, 300);
            }, index * 200);
        });
    }
    
    // Animate chain every 30 seconds
    setInterval(animateIntegrityChain, 30000);
    
    // Initialize animations
    setTimeout(animateIntegrityChain, 1000);
    
    // Stats counter animation
    const statNumbers = document.querySelectorAll('.stat-content h3');
    statNumbers.forEach(stat => {
        const targetNumber = parseInt(stat.textContent);
        let currentNumber = 0;
        const increment = targetNumber / 50; // 50 steps
        
        const updateCounter = () => {
            if (currentNumber < targetNumber) {
                currentNumber += increment;
                stat.textContent = Math.floor(currentNumber);
                setTimeout(updateCounter, 20);
            } else {
                stat.textContent = targetNumber;
            }
        };
        
        if (targetNumber > 0) {
            setTimeout(updateCounter, 500);
        }
    });
    
    // Security status pulse animation
    const statusDot = document.querySelector('.status-dot');
    if (statusDot) {
        setInterval(() => {
            statusDot.style.animation = 'none';
            setTimeout(() => {
                statusDot.style.animation = 'pulse 2s infinite';
            }, 10);
        }, 4000);
    }
    
    // Quick actions hover effects
    const actionBtns = document.querySelectorAll('.action-btn');
    actionBtns.forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            const icon = this.querySelector('i');
            if (icon) {
                icon.style.transform = 'rotate(15deg)';
                icon.style.transition = 'transform 0.3s ease';
            }
        });
        
        btn.addEventListener('mouseleave', function() {
            const icon = this.querySelector('i');
            if (icon) {
                icon.style.transform = 'rotate(0)';
            }
        });
    });
    
    // Logout confirmation
    const logoutBtn = document.querySelector('.logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to logout? Your session will end.')) {
                e.preventDefault();
            }
        });
    }
    
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl+Shift+P for panic mode
        if (e.ctrlKey && e.shiftKey && e.key === 'P') {
            e.preventDefault();
            if (panicBtn) panicBtn.click();
        }
        
        // Escape to close modal
        if (e.key === 'Escape' && panicModal && panicModal.classList.contains('active')) {
            panicModal.classList.remove('active');
            document.body.style.overflow = '';
        }
    });
    
    // Activity item click handler
    const activityItems = document.querySelectorAll('.activity-item');
    activityItems.forEach(item => {
        item.addEventListener('click', function() {
            // In production, this would open evidence detail view
            console.log('Evidence item clicked');
        });
    });
    
    // Initialize tooltips
    const tooltipElements = document.querySelectorAll('[title]');
    tooltipElements.forEach(el => {
        el.addEventListener('mouseenter', function() {
            // Simple tooltip implementation
            console.log('Tooltip:', this.title);
        });
    });
});