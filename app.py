import streamlit as st
from streamlit_autorefresh import st_autorefresh
import pyotp
import qrcode  # type: ignore
import io
import base64
import json
import hashlib
import requests
import time
from datetime import datetime
import pandas as pd

st.set_page_config(
    page_title="2FA Code Generator",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 1rem;
    }
    .code-display {
        font-size: 3rem;
        font-weight: 700;
        font-family: 'Courier New', monospace;
        letter-spacing: 0.5rem;
        text-align: center;
        padding: 1rem;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 15px;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
    }
    .timer-bar {
        height: 8px;
        background: linear-gradient(90deg, #00d4aa, #667eea);
        border-radius: 4px;
        transition: width 1s linear;
    }
    .account-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        border-radius: 15px;
        padding: 1.5rem;
        margin: 0.5rem 0;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .category-badge {
        background: linear-gradient(90deg, #667eea, #764ba2);
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .breach-safe {
        background: linear-gradient(135deg, #00d4aa 0%, #00b894 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
    }
    .breach-warning {
        background: linear-gradient(135deg, #ff6b6b 0%, #ee5a5a 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
    }
    .stButton>button {
        border-radius: 10px;
        font-weight: 600;
    }
    .info-box {
        background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

if 'accounts' not in st.session_state:
    st.session_state.accounts = []
if 'show_add_form' not in st.session_state:
    st.session_state.show_add_form = False
if 'edit_index' not in st.session_state:
    st.session_state.edit_index = None

def generate_totp_code(secret):
    try:
        totp = pyotp.TOTP(secret)
        return totp.now()
    except Exception as e:
        return "Invalid"

def get_time_remaining():
    return 30 - (int(time.time()) % 30)

def generate_qr_code(secret, account_name, issuer="2FA Generator"):
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=account_name, issuer_name=issuer)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    return base64.b64encode(buffer.getvalue()).decode()

def check_password_breach(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    try:
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
        if response.status_code == 200:
            hashes = response.text.split('\r\n')
            for h in hashes:
                if h.startswith(suffix):
                    count = int(h.split(':')[1])
                    return True, count
            return False, 0
    except:
        return None, 0

def export_accounts():
    if st.session_state.accounts:
        export_data = json.dumps(st.session_state.accounts, indent=2)
        return export_data
    return None

def import_accounts(json_data):
    try:
        accounts = json.loads(json_data)
        if isinstance(accounts, list):
            st.session_state.accounts = accounts
            return True
    except:
        pass
    return False

st.markdown('<h1 class="main-header">🔐 2FA Code Generator</h1>', unsafe_allow_html=True)
st.markdown('<p style="text-align: center; color: #666; margin-bottom: 2rem;">Secure Time-Based One-Time Password Generator with Advanced Features</p>', unsafe_allow_html=True)

if 'quick_secret' not in st.session_state:
    st.session_state.quick_secret = ""

with st.sidebar:
    st.markdown("### 📋 Menu")
    menu = st.radio(
        "Navigate",
        ["⚡ Quick 2FA", "🔢 My Codes", "➕ Add Account", "🔍 Breach Checker", "💾 Backup & Export", "📚 How It Works"],
        label_visibility="collapsed"
    )
    
    st.markdown("---")
    st.markdown("### 📊 Statistics")
    st.metric("Total Accounts", len(st.session_state.accounts))
    
    categories = {}
    for acc in st.session_state.accounts:
        cat = acc.get('category', 'Uncategorized')
        categories[cat] = categories.get(cat, 0) + 1
    
    if categories:
        st.markdown("**By Category:**")
        for cat, count in categories.items():
            st.write(f"• {cat}: {count}")

if menu == "⚡ Quick 2FA":
    st_autorefresh(interval=1000, key="quick_refresh")
    
    st.markdown("## ⚡ Quick 2FA Code Generator")
    st.markdown("Paste your secret key and the code updates **instantly** - no Enter needed!")
    
    import streamlit.components.v1 as components
    
    current_secret = st.session_state.quick_secret
    
    live_input_component = f"""
    <style>
        * {{ box-sizing: border-box; }}
        body {{ margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
        .container {{ padding: 0; }}
        .live-input {{
            width: 100%;
            padding: 14px 18px;
            font-size: 20px;
            font-family: 'Courier New', monospace;
            letter-spacing: 3px;
            border: 2px solid #667eea;
            border-radius: 12px;
            outline: none;
            transition: all 0.3s ease;
            background: linear-gradient(135deg, #f8f9ff 0%, #fff 100%);
            text-transform: uppercase;
        }}
        .live-input:focus {{
            border-color: #764ba2;
            box-shadow: 0 0 20px rgba(102, 126, 234, 0.4);
        }}
        .live-input::placeholder {{
            color: #999;
            letter-spacing: 1px;
            text-transform: none;
        }}
        .code-display {{
            font-size: 56px;
            font-weight: 700;
            font-family: 'Courier New', monospace;
            letter-spacing: 12px;
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            margin: 20px 0;
            box-shadow: 0 4px 20px rgba(102, 126, 234, 0.5);
            display: none;
        }}
        .code-display.visible {{ display: block; }}
        .timer-container {{
            display: none;
            margin: 10px 0;
        }}
        .timer-container.visible {{ display: block; }}
        .progress-bar {{
            height: 10px;
            background: #e0e0e0;
            border-radius: 5px;
            overflow: hidden;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #00d4aa, #667eea);
            transition: width 1s linear;
        }}
        .timer-text {{
            text-align: right;
            font-weight: 600;
            color: #667eea;
            margin-top: 5px;
        }}
        .error-msg {{
            color: #ff6b6b;
            text-align: center;
            padding: 10px;
            display: none;
        }}
        .error-msg.visible {{ display: block; }}
        .hint {{
            color: #888;
            font-size: 14px;
            text-align: center;
            margin-top: 15px;
            display: block;
        }}
        .hint.hidden {{ display: none; }}
    </style>
    <div class="container">
        <input 
            type="text" 
            class="live-input" 
            id="secretInput"
            placeholder="Paste your 2FA secret key here..."
            value="{current_secret}"
            autocomplete="off"
            spellcheck="false"
        />
        <div class="code-display" id="codeDisplay">------</div>
        <div class="timer-container" id="timerContainer">
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
            <div class="timer-text" id="timerText">30s</div>
        </div>
        <div class="error-msg" id="errorMsg">Invalid secret key format</div>
        <div class="hint" id="hint">Enter a Base32 secret key to generate your 2FA code</div>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jsSHA/3.3.1/sha1.min.js"></script>
    <script>
        const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        
        function base32ToBytes(base32) {{
            base32 = base32.replace(/[^A-Z2-7]/gi, '').toUpperCase();
            if (base32.length === 0) return null;
            
            let bits = '';
            for (let char of base32) {{
                let val = BASE32_CHARS.indexOf(char);
                if (val === -1) return null;
                bits += val.toString(2).padStart(5, '0');
            }}
            
            const bytes = [];
            for (let i = 0; i + 8 <= bits.length; i += 8) {{
                bytes.push(parseInt(bits.substr(i, 8), 2));
            }}
            return new Uint8Array(bytes);
        }}
        
        function generateTOTP(secret) {{
            const key = base32ToBytes(secret);
            if (!key || key.length === 0) return null;
            
            const epoch = Math.floor(Date.now() / 1000);
            const timeStep = Math.floor(epoch / 30);
            
            const timeBytes = new Uint8Array(8);
            let temp = timeStep;
            for (let i = 7; i >= 0; i--) {{
                timeBytes[i] = temp & 0xff;
                temp = Math.floor(temp / 256);
            }}
            
            const shaObj = new jsSHA("SHA-1", "UINT8ARRAY");
            shaObj.setHMACKey(key, "UINT8ARRAY");
            shaObj.update(timeBytes);
            const hmac = shaObj.getHMAC("UINT8ARRAY");
            
            const offset = hmac[hmac.length - 1] & 0x0f;
            const binary = ((hmac[offset] & 0x7f) << 24) |
                          ((hmac[offset + 1] & 0xff) << 16) |
                          ((hmac[offset + 2] & 0xff) << 8) |
                          (hmac[offset + 3] & 0xff);
            
            const otp = binary % 1000000;
            return otp.toString().padStart(6, '0');
        }}
        
        function getTimeRemaining() {{
            return 30 - (Math.floor(Date.now() / 1000) % 30);
        }}
        
        function updateDisplay() {{
            const input = document.getElementById('secretInput');
            const codeDisplay = document.getElementById('codeDisplay');
            const timerContainer = document.getElementById('timerContainer');
            const progressFill = document.getElementById('progressFill');
            const timerText = document.getElementById('timerText');
            const errorMsg = document.getElementById('errorMsg');
            const hint = document.getElementById('hint');
            
            const secret = input.value.replace(/[\\s-]/g, '').toUpperCase();
            
            if (secret.length > 0) {{
                const code = generateTOTP(secret);
                if (code) {{
                    codeDisplay.textContent = code;
                    codeDisplay.classList.add('visible');
                    timerContainer.classList.add('visible');
                    errorMsg.classList.remove('visible');
                    hint.classList.add('hidden');
                    
                    const remaining = getTimeRemaining();
                    progressFill.style.width = (remaining / 30 * 100) + '%';
                    timerText.textContent = remaining + 's';
                }} else {{
                    codeDisplay.classList.remove('visible');
                    timerContainer.classList.remove('visible');
                    errorMsg.classList.add('visible');
                    hint.classList.add('hidden');
                }}
            }} else {{
                codeDisplay.classList.remove('visible');
                timerContainer.classList.remove('visible');
                errorMsg.classList.remove('visible');
                hint.classList.remove('hidden');
            }}
        }}
        
        document.getElementById('secretInput').addEventListener('input', updateDisplay);
        setInterval(updateDisplay, 1000);
        updateDisplay();
    </script>
    """
    
    components.html(live_input_component, height=280)
    
    st.markdown("---")
    
    st.markdown("### Want to save this secret?")
    st.markdown("Use the **Add Account** page to save it permanently.")
    
    with st.expander("📚 How to find your secret key"):
        st.markdown("""
        1. Go to the website/app where you want to enable 2FA
        2. Look for "Set up authenticator" or "Enable 2FA"
        3. You'll see a QR code and usually a text secret key
        4. Copy the secret key and paste it above
        """)

elif menu == "🔢 My Codes":
    st_autorefresh(interval=1000, key="codes_refresh")
    
    st.markdown("## 🔢 Your 2FA Codes")
    
    time_remaining = get_time_remaining()
    progress = time_remaining / 30
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.progress(progress)
    with col2:
        st.markdown(f"**⏱️ {time_remaining}s**")
    
    if st.session_state.accounts:
        search = st.text_input("🔍 Search accounts", placeholder="Type to filter...")
        
        category_filter = st.selectbox(
            "Filter by category",
            ["All"] + list(set(acc.get('category', 'Uncategorized') for acc in st.session_state.accounts))
        )
        
        filtered_accounts = st.session_state.accounts
        if search:
            filtered_accounts = [acc for acc in filtered_accounts if search.lower() in acc['name'].lower() or search.lower() in acc.get('issuer', '').lower()]
        if category_filter != "All":
            filtered_accounts = [acc for acc in filtered_accounts if acc.get('category', 'Uncategorized') == category_filter]
        
        for i, account in enumerate(filtered_accounts):
            original_index = st.session_state.accounts.index(account)
            
            with st.container():
                col1, col2, col3 = st.columns([2, 2, 1])
                
                with col1:
                    st.markdown(f"**{account.get('issuer', 'Unknown')}**")
                    st.caption(account['name'])
                    if account.get('category'):
                        st.markdown(f'<span class="category-badge">{account["category"]}</span>', unsafe_allow_html=True)
                
                with col2:
                    code = generate_totp_code(account['secret'])
                    st.markdown(f'<div class="code-display">{code}</div>', unsafe_allow_html=True)
                
                with col3:
                    if st.button("📋", key=f"copy_{original_index}", help="Copy code"):
                        st.toast(f"Code {code} ready to use!")
                    if st.button("✏️", key=f"edit_{original_index}", help="Edit account"):
                        st.session_state.edit_index = original_index
                    if st.button("🗑️", key=f"delete_{original_index}", help="Delete account"):
                        st.session_state.accounts.pop(original_index)
                        st.rerun()
                    if st.button("📱", key=f"qr_{original_index}", help="Show QR"):
                        st.session_state[f"show_qr_{original_index}"] = not st.session_state.get(f"show_qr_{original_index}", False)
                
                if st.session_state.edit_index == original_index:
                    with st.expander("✏️ Edit Account", expanded=True):
                        edit_name = st.text_input("Account Name", value=account['name'], key=f"edit_name_{original_index}")
                        edit_issuer = st.text_input("Service/Issuer", value=account.get('issuer', ''), key=f"edit_issuer_{original_index}")
                        edit_category = st.selectbox(
                            "Category",
                            ["Work", "Personal", "Finance", "Social", "Gaming", "Other"],
                            index=["Work", "Personal", "Finance", "Social", "Gaming", "Other"].index(account.get('category', 'Other')) if account.get('category') in ["Work", "Personal", "Finance", "Social", "Gaming", "Other"] else 5,
                            key=f"edit_cat_{original_index}"
                        )
                        
                        col_save, col_cancel = st.columns(2)
                        with col_save:
                            if st.button("💾 Save", key=f"save_{original_index}", use_container_width=True):
                                st.session_state.accounts[original_index]['name'] = edit_name
                                st.session_state.accounts[original_index]['issuer'] = edit_issuer
                                st.session_state.accounts[original_index]['category'] = edit_category
                                st.session_state.edit_index = None
                                st.success("✅ Account updated!")
                                st.rerun()
                        with col_cancel:
                            if st.button("❌ Cancel", key=f"cancel_{original_index}", use_container_width=True):
                                st.session_state.edit_index = None
                                st.rerun()
                
                if st.session_state.get(f"show_qr_{original_index}", False):
                    qr_base64 = generate_qr_code(account['secret'], account['name'], account.get('issuer', '2FA'))
                    st.image(f"data:image/png;base64,{qr_base64}", width=200)
                
                st.markdown("---")
        
        if st.button("🔄 Refresh Codes"):
            st.rerun()
    else:
        st.info("👋 No accounts yet! Add your first 2FA account to get started.")
        if st.button("➕ Add Your First Account"):
            st.session_state.show_add_form = True
            st.rerun()

elif menu == "➕ Add Account":
    st.markdown("## ➕ Add New 2FA Account")
    
    tab1, tab2 = st.tabs(["📝 Manual Entry", "🔑 Generate New Secret"])
    
    with tab1:
        st.markdown("Enter the details from your authentication app or website:")
        
        with st.form("add_account_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                account_name = st.text_input("Account Name *", placeholder="e.g., john@example.com")
                issuer = st.text_input("Service/Issuer", placeholder="e.g., Google, GitHub")
            
            with col2:
                secret = st.text_input("Secret Key *", placeholder="Enter base32 secret", type="password")
                category = st.selectbox("Category", ["Work", "Personal", "Finance", "Social", "Gaming", "Other"])
            
            submitted = st.form_submit_button("➕ Add Account", use_container_width=True)
            
            if submitted:
                if account_name and secret:
                    try:
                        clean_secret = secret.replace(" ", "").upper()
                        pyotp.TOTP(clean_secret).now()
                        
                        new_account = {
                            'name': account_name,
                            'secret': clean_secret,
                            'issuer': issuer or "Unknown",
                            'category': category,
                            'created': datetime.now().isoformat()
                        }
                        st.session_state.accounts.append(new_account)
                        st.success(f"✅ Account '{account_name}' added successfully!")
                        st.balloons()
                    except Exception as e:
                        st.error("❌ Invalid secret key. Please check and try again.")
                else:
                    st.warning("⚠️ Please fill in all required fields.")
    
    with tab2:
        st.markdown("Generate a new secret key for setting up 2FA:")
        
        with st.form("generate_secret_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                new_account_name = st.text_input("Account Name *", placeholder="e.g., my-app-account", key="gen_name")
                new_issuer = st.text_input("Service/Issuer", placeholder="e.g., MyApp", key="gen_issuer")
            
            with col2:
                new_category = st.selectbox("Category", ["Work", "Personal", "Finance", "Social", "Gaming", "Other"], key="gen_cat")
            
            generate_btn = st.form_submit_button("🔑 Generate New Secret", use_container_width=True)
            
            if generate_btn and new_account_name:
                new_secret = pyotp.random_base32()
                
                new_account = {
                    'name': new_account_name,
                    'secret': new_secret,
                    'issuer': new_issuer or "2FA Generator",
                    'category': new_category,
                    'created': datetime.now().isoformat()
                }
                st.session_state.accounts.append(new_account)
                
                st.success("✅ New 2FA account created!")
                
                st.markdown("### Your New Secret Key:")
                st.code(new_secret)
                
                st.markdown("### Scan this QR Code:")
                qr_base64 = generate_qr_code(new_secret, new_account_name, new_issuer or "2FA Generator")
                st.image(f"data:image/png;base64,{qr_base64}", width=250)
                
                st.warning("⚠️ Save this secret key securely! You'll need it to recover your 2FA.")

elif menu == "🔍 Breach Checker":
    st.markdown("## 🔍 Password Breach Checker")
    st.markdown("Check if your passwords or emails have been exposed in known data breaches using the **Have I Been Pwned** database.")
    
    st.markdown('<div class="info-box">🔒 Your password is never sent over the internet. We use a secure k-anonymity model.</div>', unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["🔐 Check Password", "📧 Check Email"])
    
    with tab1:
        password = st.text_input("Enter a password to check", type="password", placeholder="Type your password here...")
        
        if st.button("🔍 Check Password", use_container_width=True):
            if password:
                with st.spinner("Checking..."):
                    is_breached, count = check_password_breach(password)
                    
                    if is_breached is None:
                        st.warning("⚠️ Couldn't connect to the breach database. Try again later.")
                    elif is_breached:
                        st.markdown(f'''
                        <div class="breach-warning">
                            <h3>⚠️ Password Compromised!</h3>
                            <p>This password has appeared in <strong>{count:,}</strong> data breaches.</p>
                            <p>We strongly recommend changing this password immediately!</p>
                        </div>
                        ''', unsafe_allow_html=True)
                    else:
                        st.markdown('''
                        <div class="breach-safe">
                            <h3>✅ Good News!</h3>
                            <p>This password hasn't been found in any known data breaches.</p>
                        </div>
                        ''', unsafe_allow_html=True)
            else:
                st.warning("Please enter a password to check.")
    
    with tab2:
        email = st.text_input("Enter your email to check", placeholder="your@email.com")
        
        if st.button("🔍 Check Email", use_container_width=True):
            if email:
                st.info("📧 For email breach checks, visit **haveibeenpwned.com** directly. We only support password checking via API to protect your privacy.")
                st.markdown(f"[Check your email on HIBP →](https://haveibeenpwned.com/unifiedsearch/{email})")
            else:
                st.warning("Please enter an email to check.")

elif menu == "💾 Backup & Export":
    st.markdown("## 💾 Backup & Export")
    
    tab1, tab2 = st.tabs(["📤 Export", "📥 Import"])
    
    with tab1:
        st.markdown("### Export Your Accounts")
        st.warning("⚠️ The exported file contains your secret keys. Store it securely!")
        
        if st.session_state.accounts:
            export_data = export_accounts()
            
            if export_data:
                st.download_button(
                    label="📥 Download Backup (JSON)",
                    data=export_data,
                    file_name=f"2fa_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            with st.expander("👁️ Preview Export Data"):
                st.json(st.session_state.accounts)
        else:
            st.info("No accounts to export. Add some accounts first!")
    
    with tab2:
        st.markdown("### Import Accounts")
        st.info("Upload a previously exported JSON backup file.")
        
        uploaded_file = st.file_uploader("Choose a backup file", type=['json'])
        
        if uploaded_file:
            try:
                content = uploaded_file.read().decode('utf-8')
                preview_data = json.loads(content)
                
                st.markdown(f"**Found {len(preview_data)} accounts in backup:**")
                for acc in preview_data:
                    st.write(f"• {acc.get('issuer', 'Unknown')} - {acc.get('name', 'Unknown')}")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("✅ Replace All", use_container_width=True):
                        if import_accounts(content):
                            st.success("✅ Accounts imported successfully!")
                            st.rerun()
                        else:
                            st.error("❌ Failed to import. Invalid format.")
                
                with col2:
                    if st.button("➕ Merge with Existing", use_container_width=True):
                        existing_names = [acc['name'] for acc in st.session_state.accounts]
                        added = 0
                        for acc in preview_data:
                            if acc['name'] not in existing_names:
                                st.session_state.accounts.append(acc)
                                added += 1
                        st.success(f"✅ Added {added} new accounts!")
                        st.rerun()
            except Exception as e:
                st.error(f"❌ Error reading file: {str(e)}")

elif menu == "📚 How It Works":
    st.markdown("## 📚 How TOTP Works")
    
    st.markdown("""
    ### What is TOTP?
    **Time-based One-Time Password (TOTP)** is an algorithm that generates a unique code every 30 seconds using:
    1. A **shared secret key** (stored in your authenticator app)
    2. The **current time** (synchronized between your device and the server)
    """)
    
    st.markdown("### Live Demo")
    demo_secret = "JBSWY3DPEHPK3PXP"
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Secret Key (Base32):**")
        st.code(demo_secret)
        
        st.markdown("**Current Unix Timestamp:**")
        current_time = int(time.time())
        st.code(str(current_time))
        
        st.markdown("**Time Step (30 seconds):**")
        time_step = current_time // 30
        st.code(str(time_step))
    
    with col2:
        st.markdown("**Generated TOTP Code:**")
        demo_code = generate_totp_code(demo_secret)
        st.markdown(f'<div class="code-display">{demo_code}</div>', unsafe_allow_html=True)
        
        time_remaining = get_time_remaining()
        st.progress(time_remaining / 30)
        st.caption(f"Code refreshes in {time_remaining} seconds")
    
    st.markdown("""
    ### The Algorithm
    ```
    1. Get current Unix time → 1700000000
    2. Divide by 30 (time step) → 56666666
    3. Convert secret from Base32 → binary
    4. HMAC-SHA1(secret, time_step) → hash
    5. Dynamic truncation → 6-digit code
    ```
    """)
    
    st.markdown("""
    ### Security Tips
    - 🔐 **Never share your secret keys** - They're like passwords!
    - 💾 **Keep backups** - Losing your 2FA can lock you out
    - 🔄 **Time sync matters** - Keep your device clock accurate
    - 📱 **Use on trusted devices only** - Avoid shared computers
    """)

st.markdown("---")
st.markdown(
    '''
    <div style="text-align: center; color: #888; font-size: 0.9rem;">
        <p>🔐 2FA Code Generator | Built with Streamlit | Your secrets never leave your device</p>
        <p style="margin-top: 5px;">
            Built by <a href="https://github.com/Hashyz" target="_blank" style="color: #667eea; text-decoration: none; font-weight: 600;">@Hashyz</a>
        </p>
    </div>
    ''',
    unsafe_allow_html=True
)
