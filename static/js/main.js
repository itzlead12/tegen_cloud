// Mobile Navigation Toggle
const navToggle = document.getElementById('navToggle');
const navMenu = document.getElementById('navMenu');

if (navToggle && navMenu) {
    navToggle.addEventListener('click', () => {
        navMenu.classList.toggle('active');
        navToggle.innerHTML = navMenu.classList.contains('active') 
            ? '<i class="fas fa-times"></i>' 
            : '<i class="fas fa-bars"></i>';
    });

    // Close menu when clicking a link
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', () => {
            navMenu.classList.remove('active');
            navToggle.innerHTML = '<i class="fas fa-bars"></i>';
        });
    });
}

// Smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        
        const targetId = this.getAttribute('href');
        if (targetId === '#') return;
        
        const targetElement = document.querySelector(targetId);
        if (targetElement) {
            window.scrollTo({
                top: targetElement.offsetTop - 80,
                behavior: 'smooth'
            });
        }
    });
});

// Active navigation link highlighting
window.addEventListener('scroll', () => {
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-link:not(.login-btn):not(.get-started-btn)');
    
    let current = '';
    sections.forEach(section => {
        const sectionTop = section.offsetTop - 100;
        const sectionHeight = section.clientHeight;
        if (scrollY >= sectionTop && scrollY < sectionTop + sectionHeight) {
            current = section.getAttribute('id');
        }
    });
    
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === `#${current}`) {
            link.classList.add('active');
        }
    });
});

// Security animation in hero section
const visualCard = document.querySelector('.visual-card');
if (visualCard) {
    let isHovered = false;
    
    visualCard.addEventListener('mouseenter', () => {
        isHovered = true;
        animateIntegrityBadge();
    });
    
    visualCard.addEventListener('mouseleave', () => {
        isHovered = false;
    });
    
    function animateIntegrityBadge() {
        const badge = visualCard.querySelector('.integrity-badge');
        if (badge && isHovered) {
            badge.style.transform = 'scale(1.05)';
            badge.style.transition = 'transform 0.3s ease';
            
            setTimeout(() => {
                if (isHovered) {
                    badge.style.transform = 'scale(1)';
                }
            }, 300);
        }
    }
}

// Developer card hover effect enhancement
document.querySelectorAll('.developer-card').forEach(card => {
    card.addEventListener('mouseenter', function() {
        const portrait = this.querySelector('.portrait-placeholder');
        if (portrait) {
            portrait.style.transform = 'scale(1.1)';
            portrait.style.transition = 'transform 0.3s ease';
        }
    });
    
    card.addEventListener('mouseleave', function() {
        const portrait = this.querySelector('.portrait-placeholder');
        if (portrait) {
            portrait.style.transform = 'scale(1)';
        }
    });
});

// Feature card interaction
document.querySelectorAll('.feature-card').forEach(card => {
    card.addEventListener('mouseenter', function() {
        const number = this.querySelector('.feature-number');
        if (number) {
            number.style.transform = 'scale(1.2) rotate(15deg)';
            number.style.transition = 'transform 0.3s ease';
        }
    });
    
    card.addEventListener('mouseleave', function() {
        const number = this.querySelector('.feature-number');
        if (number) {
            number.style.transform = 'scale(1) rotate(0)';
        }
    });
});

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('TEGEN-CLOUD v1.0.0 loaded successfully');
    console.log('Security features: AES-GCM encryption, SHA-256 integrity ledger');
    
    // Add loading animation
    document.body.style.opacity = '0';
    document.body.style.transition = 'opacity 0.5s ease';
    
    setTimeout(() => {
        document.body.style.opacity = '1';
    }, 100);
});