// CodeFlow Xray Panel - Public Script
// Handles Space Background, Theme, and Accent Colors

document.addEventListener('DOMContentLoaded', () => {
    initSpaceCanvas();
    initTheme();
    initAccent();
});

// ==========================================
// 1. COSMIC BACKGROUND ANIMATION (Canvas)
// ==========================================
function initSpaceCanvas() {
    const canvas = document.getElementById('spaceCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    let w = canvas.width = window.innerWidth;
    let h = canvas.height = window.innerHeight;
    
    window.addEventListener('resize', () => {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    });
    
    const count = 100;
    const stars = [];
    
    const colorMap = {
        'rose': { r: 244, g: 63, b: 94 },
        'blue': { r: 14, g: 165, b: 233 },
        'emerald': { r: 16, g: 185, b: 129 },
        'purple': { r: 168, g: 85, b: 247 }
    };
    
    let currentAccent = localStorage.getItem('accent') || 'blue';
    let targetRGB = colorMap[currentAccent] || colorMap['blue'];
    let activeRGB = { ...targetRGB };
    
    window.updateSpaceCanvasColors = function(color) {
        if (colorMap[color]) {
            targetRGB = colorMap[color];
        }
    };
    
    // Slow drifting nebulae blobs
    const nebulae = [
        { x: w * 0.25, y: h * 0.25, vx: 0.15, vy: 0.08, r: Math.min(w, h) * 0.45 },
        { x: w * 0.75, y: h * 0.65, vx: -0.08, vy: -0.12, r: Math.min(w, h) * 0.55 }
    ];
    
    for (let i = 0; i < count; i++) {
        stars.push({
            x: Math.random() * w,
            y: Math.random() * h,
            r: Math.random() * 1.5 + 0.3,
            d: Math.random() * 0.18 + 0.04, // speed
            isColored: Math.random() < 0.35, // 35% colored stars
            opacity: Math.random() * 0.6 + 0.15
        });
    }
    
    function draw() {
        ctx.clearRect(0, 0, w, h);
        
        const isLight = document.documentElement.getAttribute('data-theme') === 'light';
        
        // Smooth color interpolation for transitions
        activeRGB.r += (targetRGB.r - activeRGB.r) * 0.08;
        activeRGB.g += (targetRGB.g - activeRGB.g) * 0.08;
        activeRGB.b += (targetRGB.b - activeRGB.b) * 0.08;
        
        // Draw nebulae
        nebulae.forEach(n => {
            n.x += n.vx;
            n.y += n.vy;
            
            if (n.x < -n.r/2 || n.x > w + n.r/2) n.vx *= -1;
            if (n.y < -n.r/2 || n.y > h + n.r/2) n.vy *= -1;
            
            const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.r);
            const ambientOpacity = isLight ? 0.03 : 0.09;
            grad.addColorStop(0, `rgba(${Math.round(activeRGB.r)}, ${Math.round(activeRGB.g)}, ${Math.round(activeRGB.b)}, ${ambientOpacity})`);
            grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
            
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
            ctx.fill();
        });
        
        // Draw stars
        for (let i = 0; i < count; i++) {
            const s = stars[i];
            ctx.beginPath();
            ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
            
            if (s.isColored) {
                ctx.fillStyle = `rgba(${Math.round(activeRGB.r)}, ${Math.round(activeRGB.g)}, ${Math.round(activeRGB.b)}, ${s.opacity})`;
            } else {
                ctx.fillStyle = isLight ? `rgba(15, 23, 42, ${s.opacity})` : `rgba(255, 255, 255, ${s.opacity})`;
            }
            ctx.fill();
            
            s.y += s.d;
            if (s.y > h) {
                s.y = 0;
                s.x = Math.random() * w;
            }
        }
        requestAnimationFrame(draw);
    }
    draw();
}

// ==========================================
// 2. ACCENT THEME MANAGEMENT
// ==========================================
function initAccent() {
    let savedAccent = localStorage.getItem('accent');
    if (!savedAccent) {
        savedAccent = 'blue';
    }
    setAccent(savedAccent);
}

function setAccent(color) {
    document.documentElement.setAttribute('data-accent', color);
    localStorage.setItem('accent', color);
    
    // Update active state for all accent switcher buttons generically
    const allButtons = document.querySelectorAll('.accent-btn');
    allButtons.forEach(btn => {
        if (btn.classList.contains(`accent-${color}`)) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
    
    // Notify the space canvas to update its theme colors
    if (window.updateSpaceCanvasColors) {
        window.updateSpaceCanvasColors(color);
    }
}

// Attach changeAccent globally for HTML inline onclick
window.changeAccent = function(color) {
    setAccent(color);
};

// ==========================================
// 3. THEME THEME MANAGEMENT (Dark/Light)
// ==========================================
function initTheme() {
    let savedTheme = localStorage.getItem('theme');
    if (!savedTheme) {
        savedTheme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    setTheme(savedTheme);
    
    // Bind to all theme toggle buttons on the page
    const toggleBtns = document.querySelectorAll('.theme-toggle-btn');
    toggleBtns.forEach(btn => {
        // Clear listeners first by cloning
        const clone = btn.cloneNode(true);
        btn.replaceWith(clone);
    });
    
    const newBtns = document.querySelectorAll('.theme-toggle-btn');
    newBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            setTheme(newTheme);
        });
    });
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    
    const sunIcons = document.querySelectorAll('.theme-toggle-btn svg[id="sunIcon"]');
    const moonIcons = document.querySelectorAll('.theme-toggle-btn svg[id="moonIcon"]');
    
    if (theme === 'dark') {
        sunIcons.forEach(i => i.style.display = 'block');
        moonIcons.forEach(i => i.style.display = 'none');
    } else {
        sunIcons.forEach(i => i.style.display = 'none');
        moonIcons.forEach(i => i.style.display = 'block');
    }
}
