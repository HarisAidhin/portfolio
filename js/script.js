// DOM Elements
const hamburger = document.querySelector('.hamburger');
const navMenu = document.querySelector('.nav-menu');
const filterButtons = document.querySelectorAll('.filter-btn');
const certificateGrid = document.querySelector('.certificates-grid');
const skillProgressBars = document.querySelectorAll('.skill-progress');
const statNumbers = document.querySelectorAll('.stat-number');
const copyButtons = document.querySelectorAll('.copy-code');

// Certificate Data
const certificates = [
    {
        title: 'Diskominfo Kabupaten Bantul',
        type: 'national',
        image: 'Sertifikat/serti1.jpg',
        link: 'https://esurat.bantulkab.go.id/public/1UEPs5DrRaE7WtzY'
    },
    {
        title: 'Darmajaya CSIRT',
        type: 'national', 
        image: 'Sertifikat/serti2.jpg'
    },
    {
        title: 'Diskominfo Kota Depok',
        type: 'national',
        image: 'Sertifikat/serti3.jpg'
    },
    {
        title: 'Diskominfo Provinsi Jawa Timur',
        type: 'national',
        image: 'Sertifikat/serti4.jpg'
    },
    {
        title: 'Diskominfo Kulon Progo',
        type: 'national',
        image: 'Sertifikat/serti5.png'
    },
    {
        title: 'Sman 5 Pandeglang',
        type: 'national',
        image: 'Sertifikat/serti6.png'
    },
    {
        title: 'Smam Satu Gresik',
        type: 'national',
        image: 'Sertifikat/serti7.png'
    },
    {
        title: 'Universitas Islam Depok',
        type: 'national',
        image: 'Sertifikat/serti8.jpg'
    },
    {
        title: 'Diskominfotik Provinsi DKI Jakarta',
        type: 'national',
        image: 'Sertifikat/serti9.jpg',
        link: 'https://soc.jakarta.go.id//certificate/view?token=$2y$13$uP8RKP/oyrbbjjs./v7KHu6OeyNZNbQRSbNZ.6ohMuth8JPNM2eYq'
    },
    {
        title: 'Universitas Muhammadiyah Jambi',
        type: 'national',
        image: 'Sertifikat/serti10.jpg'
    },
    {
        title: 'Universitas Muhammadiyah Cirebon',
        type: 'national',
        image: 'Sertifikat/serti11.jpg'
    },
    {
        title: 'Diskominfo Kota Cimahi',
        type: 'national',
        image: 'Sertifikat/serti12.jpg'
    },
    {
        title: 'Avans Hogeschool',
        type: 'international',
        image: 'Sertifikat/Loa.jpg'
    },
    {
        title: 'Avans Hogeschool',
        type: 'international',
        image: 'Sertifikat/Loa2.jpg'
    },
    {
        title: 'Diskominfo DIY',
        type: 'national',
        image: 'Sertifikat/serti14.jpg',
        link: 'https://sadewa.jogjaprov.go.id/pdf?id=U2FsdGVkX1p1L2u3S71CuVnCertYAS0m24za1JHLtMRNZqRNRV0gs8YlldJFu5p1L2u3SZ7p1L2u3SS5NFrPv2q8rxqtP6lf1NT5xp1L2u3Sgge1Q2u3A4le1Q2u3A4l&document_type=targetedtte'
    },
    {
        title: 'Diskominfo Kota Bekasi',
        type: 'national',
        image: 'Sertifikat/serti15.jpg'
    },
    {
        title: 'Diskominfo Kutai Kartanegara',
        type: 'national',
        image: 'Sertifikat/serti16.jpg',
        link: 'https://ttis.kukarkab.go.id/whitehat-etam?page=3'
    },
    {
        title: 'Universitas Negeri Jakarta',
        type: 'national',
        image: 'Sertifikat/serti17.jpg'
    },
    {
        title: 'Universitas Airlangga',
        type: 'national',
        image: 'Sertifikat/serti18.jpg'
    },
    {
        title: 'Universitas Dirgantara Marsekal Suryadarma',
        type: 'national',
        image: 'Sertifikat/serti19.jpg'
    },
    {
        title: 'Sumedangkab CSIRT',
        type: 'national',
        image: 'Sertifikat/serti20.jpg'
    },
    {
        title: 'Politeknik Siber Cerdika International',
        type: 'national',
        image: 'Sertifikat/serti21.jpg'
    },
    {
        title: 'Politeknik Siber Cerdika International',
        type: 'national',
        image: 'Sertifikat/serti22.jpg'
    },
    {
        title: 'TransJakarta CSIRT',
        type: 'national',
        image: 'Sertifikat/serti23.jpg'
    },
    {
        title: 'Bpbd Kota Magelang',
        type: 'national',
        image: 'Sertifikat/serti24.jpg'
    }
    ,
    {
        title: 'Detik.com ',
        type: 'national',
        image: 'Sertifikat/serti25.jpg'
    }
];

// Mobile Navigation
hamburger.addEventListener('click', () => {
    hamburger.classList.toggle('active');
    navMenu.classList.toggle('active');
});

// Close mobile menu when clicking on links
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', () => {
        hamburger.classList.remove('active');
        navMenu.classList.remove('active');
    });
});

// Typewriter Effect
const typewriterText = document.querySelector('.typewriter-text');
if (typewriterText) {
    const texts = [
        'Security Researcher',
        'Penetration Tester',
        'Bug Hunter',
        'Web Security Specialist'
    ];
    
    let textIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    
    function typeWriter() {
        const currentText = texts[textIndex];
        
        if (isDeleting) {
            typewriterText.textContent = currentText.substring(0, charIndex - 1);
            charIndex--;
        } else {
            typewriterText.textContent = currentText.substring(0, charIndex + 1);
            charIndex++;
        }
        
        if (!isDeleting && charIndex === currentText.length) {
            isDeleting = true;
            setTimeout(typeWriter, 2000);
        } else if (isDeleting && charIndex === 0) {
            isDeleting = false;
            textIndex = (textIndex + 1) % texts.length;
            setTimeout(typeWriter, 500);
        } else {
            setTimeout(typeWriter, isDeleting ? 50 : 100);
        }
    }
    
    setTimeout(typeWriter, 1000);
}

// Load Certificates
function loadCertificates(filter = 'all') {
    certificateGrid.innerHTML = '';
    
    const filteredCerts = filter === 'all' 
        ? certificates 
        : certificates.filter(cert => cert.type === filter);
    
    filteredCerts.forEach(cert => {
        const certElement = document.createElement('div');
        certElement.className = 'certificate-item fade-in';
        
        certElement.innerHTML = `
            <img src="${cert.image}" alt="${cert.title}" class="certificate-image">
            <div class="certificate-content">
                <h4 class="certificate-title">${cert.title}</h4>
                <span class="certificate-type">${cert.type === 'national' ? 'Nasional' : 'Internasional'}</span>
                ${cert.link ? 
                    `<a href="${cert.link}" target="_blank" class="certificate-link">
                        <i class="fas fa-external-link-alt"></i> Verifikasi Sertifikat
                    </a>` : 
                    '<p class="certificate-link"><i class="fas fa-certificate"></i> Sertifikat</p>'
                }
            </div>
        `;
        
        certificateGrid.appendChild(certElement);
    });
}

// Certificate Filtering
filterButtons.forEach(button => {
    button.addEventListener('click', () => {
        // Remove active class from all buttons
        filterButtons.forEach(btn => btn.classList.remove('active'));
        // Add active class to clicked button
        button.classList.add('active');
        // Load certificates with selected filter
        loadCertificates(button.dataset.filter);
    });
});

// Animate Skill Bars
function animateSkillBars() {
    skillProgressBars.forEach(bar => {
        const width = bar.getAttribute('data-width');
        bar.style.width = `${width}%`;
    });
}

// Animate Stats Counter
function animateStats() {
    statNumbers.forEach(stat => {
        const target = parseInt(stat.getAttribute('data-count'));
        const increment = target / 100;
        let current = 0;
        
        const timer = setInterval(() => {
            current += increment;
            if (current >= target) {
                current = target;
                clearInterval(timer);
            }
            stat.textContent = Math.floor(current);
        }, 20);
    });
}

// Copy Code Button
copyButtons.forEach(button => {
    button.addEventListener('click', () => {
        const codeBlock = button.parentElement.nextElementSibling;
        const code = codeBlock.textContent;
        
        navigator.clipboard.writeText(code).then(() => {
            const originalIcon = button.innerHTML;
            button.innerHTML = '<i class="fas fa-check"></i>';
            button.style.color = '#64ffda';
            
            setTimeout(() => {
                button.innerHTML = originalIcon;
                button.style.color = '';
            }, 2000);
        });
    });
});

// Smooth Scrolling for Anchor Links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        if (this.getAttribute('href') === '#') return;
        
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

// Scroll Animations
function checkScroll() {
    const elements = document.querySelectorAll('.fade-in:not(.animated)');
    
    elements.forEach(element => {
        const elementTop = element.getBoundingClientRect().top;
        const windowHeight = window.innerHeight;
        
        if (elementTop < windowHeight - 100) {
            element.classList.add('animated');
            
            // If it's a skill bar, animate it
            if (element.classList.contains('skill-progress')) {
                const width = element.getAttribute('data-width');
                element.style.width = `${width}%`;
            }
        }
    });
}

// Intersection Observer for animations
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('animated');
            
            // Special handling for skill bars
            if (entry.target.classList.contains('skill-progress')) {
                const width = entry.target.getAttribute('data-width');
                setTimeout(() => {
                    entry.target.style.width = `${width}%`;
                }, 300);
            }
            
            // Special handling for stats
            if (entry.target.classList.contains('stat-number')) {
                const target = parseInt(entry.target.getAttribute('data-count'));
                const increment = target / 100;
                let current = 0;
                
                const timer = setInterval(() => {
                    current += increment;
                    if (current >= target) {
                        current = target;
                        clearInterval(timer);
                    }
                    entry.target.textContent = Math.floor(current);
                }, 20);
            }
        }
    });
}, observerOptions);

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
    // Load certificates
    loadCertificates();
    
    // Observe elements for animations
    document.querySelectorAll('.fade-in').forEach(el => observer.observe(el));
    
    // Animate elements already in view
    checkScroll();
    
    // Set current year in footer
    const yearSpan = document.querySelector('#current-year');
    if (yearSpan) {
        yearSpan.textContent = new Date().getFullYear();
    }
});

// Window scroll event
window.addEventListener('scroll', checkScroll);

// Initialize animations on load
window.addEventListener('load', () => {
    animateSkillBars();
    animateStats();
});