import streamlit as st
import sqlite3
import hashlib
import datetime

# Hide Streamlit menu and deploy button
st.set_page_config(page_title="DROOD and AYTA-E-KARIMA Tracker", menu_items=None)

# CSS to hide Streamlit branding, GitHub, and menu buttons
hide_streamlit_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stDeployButton {display:none;}
    iframe[title="streamlit_broadcast"] {display: none;}
    </style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)


# Database setup
# Database setup
def init_db():
    conn = sqlite3.connect('drood_tracker.db')
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        pin_hash TEXT,
        drood INTEGER,
        ayta_e_karima INTEGER
    )
    ''')
    
    # Check if activity_log table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='activity_log'")
    table_exists = c.fetchone() is not None
    
    if not table_exists:
        # Create new activity log table with date column
        c.execute('''
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            drood_added INTEGER,
            ayta_e_karima_added INTEGER,
            timestamp TEXT,
            date TEXT,
            action_type TEXT
        )
        ''')
    else:
        # Check if date column exists in activity_log table
        try:
            c.execute("SELECT date FROM activity_log LIMIT 1")
        except sqlite3.OperationalError:
            # Add date column if it doesn't exist
            c.execute("ALTER TABLE activity_log ADD COLUMN date TEXT")
            # Update existing records with date extracted from timestamp
            c.execute("UPDATE activity_log SET date = substr(timestamp, 1, 10)")
    
    conn.commit()
    conn.close()

# Hash the PIN
def hash_pin(pin):
    return hashlib.sha256(str(pin).encode()).hexdigest()

# User registration
def register_user(username, pin):
    conn = sqlite3.connect('drood_tracker.db')
    c = conn.cursor()
    
    # Check if username already exists
    c.execute("SELECT username FROM users WHERE username = ?", (username,))
    if c.fetchone() is not None:
        conn.close()
        return False
    
    # Hash the PIN and store new user
    pin_hash = hash_pin(pin)
    c.execute("INSERT INTO users VALUES (?, ?, 0, 0)", (username, pin_hash))
    conn.commit()
    conn.close()
    return True

# User authentication
def authenticate(username, pin):
    conn = sqlite3.connect('drood_tracker.db')
    c = conn.cursor()
    
    # Get stored hash for username
    c.execute("SELECT pin_hash FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    
    if result is None:
        return False
    
    stored_hash = result[0]
    return stored_hash == hash_pin(pin)

# Update counts and log activity
def update_counts(username, drood_count=0, ayta_count=0):
    conn = sqlite3.connect('drood_tracker.db')
    c = conn.cursor()
    
    # Update user counts
    c.execute("UPDATE users SET drood = drood + ?, ayta_e_karima = ayta_e_karima + ? WHERE username = ?", 
              (drood_count, ayta_count, username))
    
    # Log the activity with separate date and timestamp
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    date = now.strftime("%Y-%m-%d")
    
    c.execute("INSERT INTO activity_log (username, drood_added, ayta_e_karima_added, timestamp, date, action_type) VALUES (?, ?, ?, ?, ?, ?)",
              (username, drood_count, ayta_count, timestamp, date, "add"))
    
    conn.commit()
    conn.close()

# Get user counts
def get_user_counts(username):
    conn = sqlite3.connect('drood_tracker.db')
    c = conn.cursor()
    
    c.execute("SELECT drood, ayta_e_karima FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    
    if result:
        return result
    return (0, 0)

# Get global counts
def get_global_counts():
    conn = sqlite3.connect('drood_tracker.db')
    c = conn.cursor()
    
    c.execute("SELECT SUM(drood), SUM(ayta_e_karima) FROM users")
    result = c.fetchone()
    conn.close()
    
    if result and result[0] is not None:
        return result
    return (0, 0)

# Get activity log
def get_activity_log():
    conn = sqlite3.connect('drood_tracker.db')
    c = conn.cursor()
    
    c.execute("SELECT username, drood_added, ayta_e_karima_added, timestamp, date, action_type FROM activity_log ORDER BY timestamp DESC")
    result = c.fetchall()
    conn.close()
    
    return result

# Reset all counts
def reset_all_counts(username):
    conn = sqlite3.connect('drood_tracker.db')
    c = conn.cursor()
    
    # Get current totals before reset
    c.execute("SELECT SUM(drood), SUM(ayta_e_karima) FROM users")
    totals = c.fetchone()
    
    # Reset all users' counts
    c.execute("UPDATE users SET drood = 0, ayta_e_karima = 0")
    
    # Log the reset action with separate date and timestamp
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    date = now.strftime("%Y-%m-%d")
    
    c.execute("INSERT INTO activity_log (username, drood_added, ayta_e_karima_added, timestamp, date, action_type) VALUES (?, ?, ?, ?, ?, ?)",
              (username, -totals[0] if totals[0] else 0, -totals[1] if totals[1] else 0, timestamp, date, "reset"))
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Streamlit app
st.title("DROOD and AYTA-E-KARIMA Tracker")

# Session state initialization
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'show_reset_confirm' not in st.session_state:
    st.session_state.show_reset_confirm = False

# Login/Signup section
if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        st.subheader("Login")
        login_username = st.text_input("Username", key="login_username")
        login_pin = st.text_input("4-Digit PIN", type="password", max_chars=4, key="login_pin")
        
        if st.button("Login", key="login_button"):
            if login_username and login_pin and len(login_pin) == 4 and login_pin.isdigit():
                if authenticate(login_username, login_pin):
                    st.session_state.logged_in = True
                    st.session_state.username = login_username
                    st.rerun()
                else:
                    st.error("Invalid credentials")
            else:
                st.error("Please enter a valid username and 4-digit PIN")
    
    with tab2:
        st.subheader("Sign Up")
        signup_username = st.text_input("Username", key="signup_username")
        signup_pin = st.text_input("4-Digit PIN", type="password", max_chars=4, key="signup_pin")
        confirm_pin = st.text_input("Confirm PIN", type="password", max_chars=4, key="confirm_pin")
        
        if st.button("Sign Up", key="signup_button"):
            if signup_username and signup_pin and confirm_pin:
                if len(signup_pin) != 4 or not signup_pin.isdigit():
                    st.error("PIN must be a 4-digit number")
                elif signup_pin != confirm_pin:
                    st.error("PINs do not match")
                else:
                    if register_user(signup_username, signup_pin):
                        st.success("Account created successfully! Please login.")
                    else:
                        st.error("Username already exists")
            else:
                st.error("Please fill in all fields")

# Main app after login
else:
    st.write(f"Welcome, {st.session_state.username}!")
    
    # Get current counts
    user_drood, user_ayta = get_user_counts(st.session_state.username)
    
    # Display user stats
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Your DROOD Count", user_drood)
    with col2:
        st.metric("Your AYTA-E-KARIMA Count", user_ayta)
    
    # Add counts section
    st.subheader("Add to Your Counts")
    
    add_col1, add_col2 = st.columns(2)
    with add_col1:
        new_drood = st.number_input("DROOD to add", min_value=0, step=1, value=0)
    with add_col2:
        new_ayta = st.number_input("AYTA-E-KARIMA to add", min_value=0, step=1, value=0)
    
    if st.button("Add Counts"):
        if new_drood > 0 or new_ayta > 0:
            update_counts(st.session_state.username, new_drood, new_ayta)
            st.success(f"Added {new_drood} DROOD and {new_ayta} AYTA-E-KARIMA to your counts!")
            st.rerun()
    
    # Global stats
    st.subheader("Global Statistics")
    global_drood, global_ayta = get_global_counts()
    
    global_col1, global_col2 = st.columns(2)
    with global_col1:
        st.metric("Global DROOD Count", global_drood)
    with global_col2:
        st.metric("Global AYTA-E-KARIMA Count", global_ayta)
    
    # Reset functionality
    st.subheader("Reset All Counts")
    
    if not st.session_state.show_reset_confirm:
        if st.button("Reset All Counts"):
            st.session_state.show_reset_confirm = True
            st.rerun()
    else:
        st.warning("⚠️ This will reset ALL users' counts to zero. This action cannot be undone.")
        confirm = st.checkbox("I understand and want to proceed with the reset")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Confirm Reset"):
                if confirm:
                    reset_all_counts(st.session_state.username)
                    st.session_state.show_reset_confirm = False
                    st.success("All counts have been reset to zero!")
                    st.rerun()
                else:
                    st.error("Please check the confirmation box to proceed")
        with col2:
            if st.button("Cancel"):
                st.session_state.show_reset_confirm = False
                st.rerun()
    
    # Activity Log
    st.subheader("Activity Log")
    activity_log = get_activity_log()
    
    if activity_log:
        # Convert to DataFrame for better display
        import pandas as pd
        log_df = pd.DataFrame(activity_log, columns=["Username", "DROOD Added", "AYTA-E-KARIMA Added", "Timestamp", "Date", "Action Type"])
        st.dataframe(log_df, use_container_width=True)
    else:
        st.info("No activity recorded yet.")
    
    # Logout button
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.show_reset_confirm = False
        st.rerun()
