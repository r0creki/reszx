// State
let isAuthenticated = false;
let currentUser = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    updateScriptStats();
    setupScrollAnimation();
    loadPricing();
    loadFAQ();
    checkHash();
    updateMemberCount();
    encryptPaths();
    checkGenerateFromRedirect();
    
    // Load scripts if on scripts page
    if (document.getElementById('scriptsGrid')) {
        loadScripts();
    }
});

// ===== AUTHENTICATION =====

function openAuthModal() {
    document.getElementById('authModal')?.classList.add('active');
}

function closeAuthModal() {
    document.getElementById('authModal')?.classList.remove('active');
}

function updateScriptStats() {
    const totalGames = scriptDatabase.length;
    let totalExecutions = 0;

    scriptDatabase.forEach(s => {
        totalExecutions += parseInt(s.uses.replace(/,/g,'')) || 0;
    });

    const gamesEl = document.getElementById("gamesCount");
    const execEl = document.getElementById("executionsCount");

    if (gamesEl) gamesEl.textContent = totalGames;
    if (execEl) execEl.textContent = totalExecutions.toLocaleString();
}

async function checkAuth() {
    if (!data.authenticated) {
    isAuthenticated = false;
    currentUser = null;
}

    try {
        const res = await fetch("/api/me");
        const data = await res.json();

        if (data.authenticated) {
            isAuthenticated = true;
            currentUser = data.user;

            document.querySelectorAll('.auth-required').forEach(e => e.style.display = 'none');
            document.querySelectorAll('.key-input-field').forEach(e => e.disabled = false);
            document.querySelectorAll('.redeem-btn').forEach(e => e.disabled = false);

            const labels = document.querySelectorAll('#loginLabel');
            labels.forEach(l => l.textContent = data.user.username);

            const avatarUrl = `https://cdn.discordapp.com/avatars/${data.user.id}/${data.user.avatar}.png`;

            const dropdown = document.getElementById("userDropdown");
            if (dropdown) {
                dropdown.innerHTML = `
                    <div class="profile-card">
                        <img src="${avatarUrl}" class="profile-avatar">
                        <div class="profile-info">
                            <div class="profile-name">${data.user.username}</div>
                            <div class="profile-id">ID: ${data.user.id}</div>
                        </div>
                        <button class="logout-btn" onclick="logout()">Logout</button>
                    </div>
                `;
            }

        }
    } catch {}
}

function closeSuccessModal() {
    document.getElementById('successModal')?.classList.remove('active');
}

// ===== NAVIGATION =====
function setupScrollAnimation() {
    const sections = document.querySelectorAll('section');
    const navItems = document.querySelectorAll('.nav-item, .mobile-nav-item');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                
                const id = entry.target.getAttribute('id');
                if (id) {
                    navItems.forEach(item => {
                        const href = item.getAttribute('href');
                        if (href && href.includes(id)) {
                            item.classList.add('active');
                        } else {
                            item.classList.remove('active');
                        }
                    });
                }
            }
        });
    }, { threshold: 0.3 });
    
    sections.forEach(section => observer.observe(section));
}

function checkHash() {
    const hash = window.location.hash;
    if (hash && hash !== '#access-denied') {
        const target = document.querySelector(hash);
        if (target) {
            setTimeout(() => target.scrollIntoView({ behavior: 'smooth' }), 100);
        }
    }
}

// ===== TABS =====
function switchTab(tabName) {
    document.querySelectorAll('.main-tab').forEach(btn => {
        if (btn.tagName === 'BUTTON') {
            btn.classList.remove('active');
        }
    });
    
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    event.target.closest('.main-tab').classList.add('active');
    document.getElementById(tabName + 'Tab').classList.add('active');
}

// ===== PRICING =====
function loadPricing() {
    const container = document.getElementById('pricingContainer');
    if (!container) return;
    
    const plans = [
        {
            name: 'Free',
            price: '0',
            period: 'Forever',
            features: [
                '2 Hour Keys via Ads',
                'Script Access',
                'Community Support',
                '1 HWID Reset per Key'
            ],
            button: 'Get Free Key'
        },
        {
            name: 'Premium',
            price: '2.49',
            period: 'Monthly',
            features: [
                'Monthly Key',
                'Selected Premium Scripts',
                'Priority Support',
                'Exclusive Discord Role'
            ],
            button: 'Get Premium',
            popular: true
        },
        {
            name: 'Premium',
            price: '8.49',
            period: '6 Months',
            features: [
                '6 Months Key',
                'Selected Premium Scripts',
                'Priority Support',
                'Unlimited HWID Resets',
                'Early Access to New Scripts',
                'Exclusive Discord Role'
            ],
            button: 'Get Premium'
        }
    ];
    
    let html = '';
    plans.forEach(plan => {
        html += `
            <div class="pricing-card ${plan.popular ? 'popular' : ''}">
                ${plan.popular ? '<div class="popular-badge">MOST POPULAR</div>' : ''}
                <div class="pricing-name">${plan.name}</div>
                <div class="pricing-price">
                    $${plan.price}
                    <small>USD</small>
                </div>
                <div class="pricing-period">${plan.period}</div>
                
                <div class="pricing-features">
                    <div class="features-header">BENEFIT (hover for details)</div>
                    <ul>
                        ${plan.features.map(f => `
                            <li class="feature-item" title="${f}">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M20 6 9 17l-5-5"></path>
                                </svg>
                                <span>${f}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
                
                <button class="pricing-btn" onclick="handlePlanClick('${plan.name}', ${plan.price})">
                    ${plan.button}
                </button>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function handlePlanClick(name, price) {
    if (price === 0) {
        window.open('https://work.ink/pevolution', '_blank');
    } else {
        if (!isAuthenticated) {
            openAuthModal();
        } else {
            alert(`✓ Redirecting to payment for ${name} plan ($${price})`);
        }
    }
}

// ===== FAQ =====
function loadFAQ() {
    const container = document.getElementById('faqContainer');
    if (!container) return;
    
    const faqs = [
        {
            q: 'What is pevolution?',
            a: 'pevolution is a powerful script provider for Roblox that allows you to run custom scripts. It\'s available on Windows, macOS, and mobile devices.'
        },
        {
            q: 'Is pevolution safe to use?',
            a: 'Yes! Our scripts are designed with safety in mind. We use anti-detection methods and regularly update our scripts to minimize any risks.'
        },
        {
            q: 'What platforms are supported?',
            a: 'We support Windows, macOS, and mobile platforms. Check our Discord for the full list of compatible executors.'
        },
        {
            q: 'How do I get a license key?',
            a: 'You can get a free key via Work.ink or purchase a premium key. Keys are bound to your device (HWID) for security.'
        },
        {
            q: 'Can I transfer my license?',
            a: 'Free keys have 1 HWID reset. Premium keys have unlimited resets through our Discord support.'
        }
    ];
    
    let html = '';
    faqs.forEach((faq, index) => {
        html += `
            <div class="faq-item">
                <button class="faq-question" onclick="toggleFaq(${index})">
                    <span>${faq.q}</span>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="m6 9 6 6 6-6"></path>
                    </svg>
                </button>
                <div class="faq-answer" id="faq-${index}">${faq.a}</div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function toggleFaq(index) {
    const answer = document.getElementById(`faq-${index}`);
    const button = answer?.previousElementSibling;
    
    if (answer && button) {
        answer.classList.toggle('show');
        button.classList.toggle('active');
    }
}

// ===== KEY FUNCTIONS =====
function redeemKey() {
    if (!isAuthenticated) {
        openAuthModal();
        return;
    }
    
    const input = document.getElementById('keyInput');
    if (!input) return;
    
    const key = input.value.trim();
    if (key) {
        if (key.startsWith('PEVO-') && key.split('-').length === 4) {
            alert('✓ Key redeemed successfully!');
            input.value = '';
        } else {
            alert('Invalid key format. Use: PEVO-XXXX-XXXX-XXXX');
        }
    } else {
        alert('Please enter a key');
    }
}

function copyLoaderScript() {
    if (!isAuthenticated) {
        openAuthModal();
        return;
    }
    
    const script = 'loadstring(game:HttpGet("https://reszx.vercel.app/api/script/loader"))()';
    navigator.clipboard.writeText(script).then(() => {
        const btn = document.querySelector('.copy-btn');
        const original = btn.innerHTML;
        btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"></path></svg><span>Copied!</span>';
        setTimeout(() => btn.innerHTML = original, 2000);
    });
}

// ===== SCRIPTS =====
const scriptDatabase = [
    {
        id: 'bf10d3b960442ff45c53ce9a2aa618b5',
        name: 'Violence District',
        description: 'Violence District is a casual asymmetrical horror game where 5 survivors have to survive against a killer.',
        uses: '15,728',
        status: 'working',
        version: 'v2.0.0b'
    },
    {
        id: '8f7d2c1e5a3b9f4d6e8c2a1b7d4e9f3c',
        name: 'Last Letter',
        description: 'Welcome to Last Letter! Play word games against people where every last letter counts.',
        uses: '235',
        status: 'working',
        version: 'v2.0.0b'
    },
    {
        id: '3e8d1b7f4c9a2e6d5b8f1c3a7d4e9f2b',
        name: 'Solo Hunter',
        description: 'Hunt solo or with friends in this intense hunting experience.',
        uses: '6,432',
        status: 'maintenance',
        version: 'v1.5.0'
    }
];

let currentScripts = [...scriptDatabase];

function loadScripts() {
    const grid = document.getElementById('scriptsGrid');
    const loading = document.getElementById('loadingState');
    const gamesCount = document.getElementById('gamesCount');
    const executionsCount = document.getElementById('executionsCount');
    
    if (!grid) return;
    
    loading.style.display = 'flex';
    grid.style.display = 'none';
    
    setTimeout(() => {
        loading.style.display = 'none';
        grid.style.display = 'grid';
        
        let html = '';
        currentScripts.forEach(script => {
            const isWorking = script.status === 'working';
            html += `
                <div class="script-card ${isWorking ? '' : 'maintenance'}">
                    <div class="script-header">
                        <div>
                            <h3 class="script-title">${script.name}</h3>
                            <span class="script-version">${script.version}</span>
                        </div>
                        <span class="script-status ${script.status}">
                            ${script.status === 'working' ? 'Working' : 'Maintenance'}
                        </span>
                    </div>
                    <p class="script-description">${script.description}</p>
                    <div class="script-meta">
                        <span class="script-uses">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <path d="M12 6v6l4 2"></path>
                            </svg>
                            ${script.uses} uses
                        </span>
                    </div>
                    <div class="script-code">
                        <div class="code-preview">
                            <span class="code-function">loadstring</span>(<span class="code-function">game</span>:<span class="code-method">HttpGet</span>("<span class="code-string encrypted-url">https://reszx.vercel.app/api/script/${script.id}</span>"))()
                        </div>
                        <button class="copy-btn small" onclick="copyScript('${script.id}')" ${!isWorking ? 'disabled' : ''}>
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect>
                                <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path>
                            </svg>
                            Copy
                        </button>
                    </div>
                </div>
            `;
        });
        
        grid.innerHTML = html;
        
        if (gamesCount) gamesCount.textContent = scriptDatabase.length;
        if (executionsCount) {
            const total = scriptDatabase.reduce((acc, s) => acc + parseInt(s.uses.replace(',', '')), 0);
            executionsCount.textContent = total.toLocaleString();
        }
        
        encryptPaths();
    }, 800);
}

function filterScripts() {
    const search = document.getElementById('searchInput')?.value.toLowerCase() || '';
    const status = document.getElementById('statusFilter')?.value || 'all';
    
    currentScripts = scriptDatabase.filter(s => {
        const matchesSearch = s.name.toLowerCase().includes(search) || s.description.toLowerCase().includes(search);
        const matchesStatus = status === 'all' || s.status === status;
        return matchesSearch && matchesStatus;
    });
    
    loadScripts();
}

function copyScript(id) {
    if (!isAuthenticated) {
        openAuthModal();
        return;
    }
    
    const script = `loadstring(game:HttpGet("https://reszx.vercel.app/api/script/${id}"))()`;
    
    if (Math.random() < 0.1) {
        showAccessDenied();
        return;
    }
    
    navigator.clipboard.writeText(script).then(() => {
        alert('✓ Script copied to clipboard!');
    });
}

// ===== ACCESS DENIED =====
function showAccessDenied() {
    const denied = document.getElementById('accessDenied');
    if (!denied) return;
    
    denied.classList.add('active');
    let seconds = 5;
    const countdown = document.getElementById('countdown');
    
    const timer = setInterval(() => {
        seconds--;
        if (countdown) countdown.textContent = seconds;
        if (seconds <= 0) {
            clearInterval(timer);
            window.location.href = 'index.html';
        }
    }, 1000);
}

function handleWorkinkClick() {
    if (!isAuthenticated) {
        openAuthModal();
        return;
    }

    window.location.href =
        "https://work.ink/YOUR_LINK?redirect=https://reszx.vercel.app/?generate=free";
}

// ===== ENCRYPTION =====
function encryptPaths() {
    document.querySelectorAll('.encrypted-url').forEach(el => {
        el.textContent = '"' + '•'.repeat(30) + '"';
    });
}

// ===== MEMBER COUNT =====
async function updateMemberCount() {
    try {
        const res = await fetch('/api/discord-members');
        const data = await res.json();

        const el = document.getElementById('memberCount');
        if (el) {
            el.textContent = data.count.toLocaleString();
        }
    } catch (e) {
        console.error("Failed to fetch member count");
    }
}

function authorizeDiscord() {
    window.location.href = "/api/login";
}

async function logout() {
    await fetch("/api/logout", {
        method: "GET",
        credentials: "include"
    });

    // reset state manual
    isAuthenticated = false;
    currentUser = null;

    // ganti label navbar
    document.querySelectorAll('#loginLabel').forEach(l => {
        l.textContent = "Login";
    });

    // reload
    window.location.href = "/";
}

async function checkGenerateFromRedirect() {
    const params = new URLSearchParams(window.location.search);

    if (params.get("generate") !== "free") return;
    if (!isAuthenticated) return;

    try {
        const res = await fetch("/api/free-key");
        const data = await res.json();

        if (data.key) {
            showKeyModal(data.key, "2 Hours");

            // Bersihkan query biar gak regenerate lagi
            window.history.replaceState({}, document.title, "/");
        }
    } catch (err) {
        console.error("Failed to generate key");
    }
}

function showKeyModal(key, duration) {
    document.getElementById("generatedKey").textContent = key;
    document.getElementById("keyDuration").textContent =
        "Duration: " + duration;

    document.getElementById("keyModal").classList.add("active");
}

function closeKeyModal() {
    document.getElementById("keyModal").classList.remove("active");
}

function copyGeneratedKey() {
    const key = document.getElementById("keyValue").textContent;
    navigator.clipboard.writeText(key);
    alert("✓ Key copied!");
}

function handleUserNavClick() {
    if (!isAuthenticated) {
        openAuthModal();
        return;
    }

    openProfileModal();
}

function openProfileModal() {
    if (!currentUser) return;

    document.getElementById("profileAvatar").src =
        `https://cdn.discordapp.com/avatars/${currentUser.id}/${currentUser.avatar}.png`;

    document.getElementById("profileUsername").textContent =
        currentUser.username;

    document.getElementById("profileId").textContent =
        `Discord ID: ${currentUser.id}`;

    document.getElementById("profileModal").classList.add("active");
}

function closeProfileModal() {
    document.getElementById("profileModal").classList.remove("active");
}

// ===== EXPORT =====
window.switchTab = switchTab;
window.openAuthModal = openAuthModal;
window.closeAuthModal = closeAuthModal;
window.authorizeDiscord = authorizeDiscord;
window.closeSuccessModal = closeSuccessModal;
window.redeemKey = redeemKey;
window.copyLoaderScript = copyLoaderScript;
window.toggleFaq = toggleFaq;
window.handlePlanClick = handlePlanClick;
window.filterScripts = filterScripts;
window.copyScript = copyScript;
window.closeKeyModal = closeKeyModal;
