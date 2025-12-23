// Dashboard JavaScript

document.addEventListener('DOMContentLoaded', function() {
    console.log('TEGEN-CLOUD Dashboard loaded');
    
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
            } else {
                // Remove active class from all links
                navLinks.forEach(l => l.classList.remove('active'));
                // Add active class to clicked link if it's a dashboard link
                if (this.href.includes(window.location.pathname)) {
                    this.classList.add('active');
                }
            }
        });
    });
    
    // Stats counter animation
    const statNumbers = document.querySelectorAll('.stat-content h3');
    statNumbers.forEach(stat => {
        const text = stat.textContent.trim();
        // Check if it's a number
        if (!isNaN(parseFloat(text)) && isFinite(text)) {
            const targetNumber = parseFloat(text);
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
    
    // Activity item click handler
    const activityItems = document.querySelectorAll('.activity-item');
    activityItems.forEach(item => {
        item.addEventListener('click', function() {
            // In production, this could navigate to evidence detail view
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
    
    // Set active nav link based on current page
    const currentPath = window.location.pathname;
    navLinks.forEach(link => {
        const linkPath = new URL(link.href).pathname;
        if (linkPath === currentPath) {
            link.classList.add('active');
        }
    });
});
