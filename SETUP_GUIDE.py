"""
SETUP GUIDE FOR SAFEGUARD NEXUS WEB APPLICATION
============================================

This guide explains how to set up and run the web-based visitor check-in system.
"""

# ════════════════════════════════════════════════════════════════
# STEP 1: INSTALL REQUIRED PACKAGES
# ════════════════════════════════════════════════════════════════

print("""
STEP 1: INSTALL DEPENDENCIES
═══════════════════════════════════════════════════════════════

Run these commands in your terminal/command prompt:

    pip install flask flask-cors pillow opencv-python numpy psutil

OR create a requirements.txt file with this content:

    flask==2.3.2
    flask-cors==4.0.0
    pillow==10.0.0
    opencv-python==4.8.0.74
    numpy==1.24.3
    psutil==5.9.5

Then run:
    pip install -r requirements.txt
""")

# ════════════════════════════════════════════════════════════════
# STEP 2: FILE STRUCTURE
# ════════════════════════════════════════════════════════════════

print("""
STEP 2: CREATE FOLDER STRUCTURE
═══════════════════════════════════════════════════════════════

Your project should look like:

    safeguard-nexus/
    ├── app.py                          (Flask web server)
    ├── safeguard.py                    (Original desktop app - kept for reference)
    ├── safeguard_vault.db              (Database - auto-created)
    ├── encodings.pickle                (Face data - from your main app)
    ├── requirements.txt                (Dependencies list)
    │
    ├── templates/                      (HTML files)
    │   ├── index.html                  (Home page)
    │   ├── gate_entry.html             (Visitor check-in form)
    │   └── dashboard.html              (View logs)
    │
    ├── static/                         (CSS, JS - optional)
    │
    └── snapshots/
        ├── verified/                   (Staff photos)
        ├── strangers/                  (Unknown intruders)
        └── visitors/                   (Visitor photos - auto-created)
""")

# ════════════════════════════════════════════════════════════════
# STEP 3: CONFIGURATION
# ════════════════════════════════════════════════════════════════

print("""
STEP 3: CONFIGURATION
═══════════════════════════════════════════════════════════════

Edit app.py if you need to change:

    PORT: Change port 5000 to anything else
        app.run(host='0.0.0.0', port=8000)  # Change 5000 to 8000

    DATABASE: Change database filename
        DATABASE = 'my_database.db'

    UPLOAD FOLDER: Change where photos are saved
        UPLOAD_FOLDER = 'my_photos'

    DEBUG MODE: For production, set to False
        app.run(..., debug=False)
""")

# ════════════════════════════════════════════════════════════════
# STEP 4: RUNNING THE WEB APP
# ════════════════════════════════════════════════════════════════

print("""
STEP 4: RUN THE APPLICATION
═══════════════════════════════════════════════════════════════

Option A: FROM COMMAND LINE
────────────────────────────────────
Windows:
    python app.py

Linux/Mac:
    python3 app.py

You should see output like:
    WARNING in app.run(...)
     * Running on http://127.0.0.1:5000
     * Press CTRL+C to quit


Option B: FROM PYTHON CODE
────────────────────────────────────
Create a file called run.py:

    if __name__ == '__main__':
        import sys
        sys.path.insert(0, '.')
        from app import app, create_visitor_table
        
        create_visitor_table()
        app.run(host='0.0.0.0', port=5000, debug=True)

Then run:
    python run.py
""")

# ════════════════════════════════════════════════════════════════
# STEP 5: ACCESSING THE WEB APP
# ════════════════════════════════════════════════════════════════

print("""
STEP 5: OPEN IN BROWSER
═══════════════════════════════════════════════════════════════

On the COMPUTER (Server):
────────────────────────────
    http://localhost:5000
    or
    http://127.0.0.1:5000

On the GUARD'S PHONE/TABLET (Same WiFi):
────────────────────────────────────────
    http://192.168.1.5:5000
    
    (Replace 192.168.1.5 with your server's IP address)

HOW TO FIND SERVER IP ADDRESS:

Windows:
    Open Command Prompt and type:
        ipconfig
    Look for "IPv4 Address" (usually starts with 192.168 or 10.)

Linux/Mac:
    Open Terminal and type:
        ifconfig
    Look for "inet" address

Example: If your IP is 192.168.1.100, guard types:
    http://192.168.1.100:5000
""")

# ════════════════════════════════════════════════════════════════
# STEP 6: NETWORK SETUP
# ════════════════════════════════════════════════════════════════

print("""
STEP 6: NETWORK CONFIGURATION
═══════════════════════════════════════════════════════════════

REQUIREMENT: Server and Guard's phone must be on SAME WiFi network

Setup Process:
──────────────

1. Make sure your desktop/server is connected to WiFi
   
2. Find your server's IP address:
   - Windows: Command Prompt → ipconfig
   - Linux/Mac: Terminal → ifconfig
   
3. Guard connects phone to SAME WiFi network
   
4. In phone browser, type: http://[SERVER_IP]:5000
   Example: http://192.168.1.5:5000

5. Test connection:
   - Server runs: http://localhost:5000
   - Phone runs: http://192.168.1.5:5000
   (Both should show same page)


FIREWALL ISSUES?
────────────────
If you can't access from phone, allow Flask through firewall:

Windows Firewall:
    1. Settings → Privacy & Security → Firewall
    2. Allow app through firewall
    3. Find Python and allow it

Linux:
    sudo ufw allow 5000

Mac:
    System Preferences → Security & Privacy → Firewall Options
""")

# ════════════════════════════════════════════════════════════════
# STEP 7: USING THE WEB APP
# ════════════════════════════════════════════════════════════════

print("""
STEP 7: SECURITY GUARD WORKFLOW
═══════════════════════════════════════════════════════════════

AT THE GATE:
────────────

1. Guard has phone/tablet with WiFi access
   
2. Opens browser and goes to: http://192.168.1.5:5000/gate-entry
   
3. Visitor arrives, Guard says:
   "Let me quickly log you in"
   
4. Guard fills the form:
   ✓ Name: "John Smith"
   ✓ Purpose: "Meeting" (dropdown)
   ✓ Contact Person: "Mr. Ahmed"
   ✓ Phone: "+1-234-567-8900" (optional)
   ✓ Photo: Clicks to upload or take photo
   
5. Click "✓ LOG ENTRY"
   
6. System confirms: "✓ John Smith checked in at 10:45:30"
   
7. Visitor can enter!
   
8. All data saved to database with photo


TO VIEW ALL LOGS:
─────────────────
Admin/Staff can visit:
    http://192.168.1.5:5000/dashboard
    
(This page will show all visitor logs with photos)
""")

# ════════════════════════════════════════════════════════════════
# STEP 8: DATABASE & FILES
# ════════════════════════════════════════════════════════════════

print("""
STEP 8: WHERE DATA IS STORED
═══════════════════════════════════════════════════════════════

DATABASE (safeguard_vault.db):
──────────────────────────────
Contains two tables:

1. logs (existing):
   - For biometric scanning data
   - Staff/intruder detection
   
2. visitor_logs (new):
   - Visitor check-in data
   - Columns: name, purpose, contact_person, phone, 
             entry_time, photo_path, status

PHOTOS:
──────
Location: snapshots/visitors/

Format: [VisitorName]_[Timestamp].jpg
Example: John_Smith_1715000000.jpg


ACCESSING DATA:
───────────────
You can query the database using SQLite:

    sqlite3 safeguard_vault.db
    > SELECT * FROM visitor_logs;
    > SELECT * FROM visitor_logs WHERE DATE(entry_time) = '2024-05-06';
""")

# ════════════════════════════════════════════════════════════════
# STEP 9: API ENDPOINTS
# ════════════════════════════════════════════════════════════════

print("""
STEP 9: API ENDPOINTS (FOR DEVELOPERS)
═══════════════════════════════════════════════════════════════

Available API routes:

HOME PAGE:
──────────
GET /
    Returns: Home page with menu

VISITOR CHECK-IN:
──────────────────
GET /gate-entry
    Returns: Visitor check-in form

POST /api/visitor-checkin
    Required fields:
        - name (text)
        - purpose (text)
        - contact_person (text)
        - phone (text, optional)
        - photo (file)
    Returns: JSON with success/error message

GET /api/visitor-logs?limit=20
    Returns: Recent visitor logs (JSON)

GET /api/visitor-search?name=John&date=2024-05-06
    Returns: Filtered visitor logs (JSON)

GET /api/visitor-stats
    Returns: Visitor statistics (JSON)
        - today: count of today's visitors
        - total: all-time visitors
        - by_purpose: breakdown by purpose

GET /snapshots/visitors/<filename>
    Returns: Visitor photo file
""")

# ════════════════════════════════════════════════════════════════
# STEP 10: TROUBLESHOOTING
# ════════════════════════════════════════════════════════════════

print("""
STEP 10: TROUBLESHOOTING
═══════════════════════════════════════════════════════════════

PROBLEM: "ModuleNotFoundError: No module named 'flask'"
─────────────────────────────────────────────────────────
Solution:
    pip install flask flask-cors

PROBLEM: "Address already in use" on port 5000
──────────────────────────────────────────────
Solution: Change port in app.py
    app.run(host='0.0.0.0', port=8000, debug=True)

PROBLEM: Can't access from phone
─────────────────────────────────
Solution:
    1. Check both devices on same WiFi
    2. Find server IP: ipconfig (Windows) or ifconfig (Linux/Mac)
    3. Use: http://[IP]:5000 on phone
    4. Check firewall settings

PROBLEM: Photos not saving
──────────────────────────
Solution:
    1. Check snapshots/visitors/ folder exists
    2. Check write permissions on folder
    3. Check disk space available

PROBLEM: Database locked error
──────────────────────────────
Solution:
    1. Close all database connections
    2. Restart Flask app
    3. Make sure app.py uses check_same_thread=False
""")

# ════════════════════════════════════════════════════════════════
# STEP 11: INTEGRATION WITH DESKTOP APP
# ════════════════════════════════════════════════════════════════

print("""
STEP 11: RUNNING BOTH DESKTOP & WEB APP
═══════════════════════════════════════════════════════════════

You can run BOTH applications simultaneously:

TERMINAL 1 - Web Server:
───────────────────────
    python app.py
    
    Access at: http://localhost:5000

TERMINAL 2 - Desktop App:
──────────────────────────
    python safeguard.py
    
    Opens GUI window with face recognition


SHARED DATABASE:
─────────────────
Both apps use the SAME database (safeguard_vault.db)

Data flow:
    Desktop App → Database ← Web App
    
- Desktop: Logs staff/intruder detections
- Web: Logs visitor check-ins
- Both visible in Analytics dashboard
""")

# ════════════════════════════════════════════════════════════════
# STEP 12: DEPLOYMENT (OPTIONAL)
# ════════════════════════════════════════════════════════════════

print("""
STEP 12: PRODUCTION DEPLOYMENT (OPTIONAL)
═══════════════════════════════════════════════════════════════

For production (not just testing):

1. Use WSGI server instead of Flask development server:
   
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 app:app

2. Set debug=False in app.py

3. Use HTTPS (SSL certificate)

4. Setup reverse proxy (nginx)

5. Database backup: cp safeguard_vault.db backup.db

Note: For school environment, development server is fine!
""")

# ════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════

print("""
╔════════════════════════════════════════════════════════════════╗
║           SAFEGUARD NEXUS - QUICK START GUIDE                  ║
╚════════════════════════════════════════════════════════════════╝

SUMMARY OF SETUP:
─────────────────
1. ✓ Install packages: pip install -r requirements.txt
2. ✓ Create folder structure (already done)
3. ✓ Run Flask server: python app.py
4. ✓ Access on phone: http://192.168.1.5:5000/gate-entry
5. ✓ Guard logs visitors with photos
6. ✓ Data syncs automatically to database

THAT'S IT! 🎉

Guard's Experience:
──────────────────
Visitor arrives → Guard opens phone → Fills form in 30 seconds → 
Takes/uploads photo → Clicks submit → Visitor enters ✓

Admin's Experience:
──────────────────
Can view all logs → Search visitors → Export data → Analyze patterns

Questions? Check the troubleshooting section above.
""")
