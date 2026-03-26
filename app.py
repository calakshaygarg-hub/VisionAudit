import streamlit as st
import pdfplumber
import imagehash
from PIL import Image
from supabase import create_client, Client

# --- 1. CORE SETUP & CONNECTION ---
st.set_page_config(page_title="VisionAudit Forensic Vault", layout="wide")

try:
    # Connects to your Supabase instance using secrets
    supabase: Client = create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])
except Exception as e:
    st.error("Connection Error: Please check your Streamlit Secrets.")
    st.stop()

# --- 2. AUDITOR AUTHENTICATION ---
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    st.title("🔐 VisionAudit Secure Access")
    pw = st.text_input("Enter Access Key", type="password")
    if st.button("Login"):
        if pw == "Audit2026!":
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Invalid Key")
    st.stop()

# --- 3. AUDIT INTERFACE ---
st.title("🔍 VisionAudit: Forensic Vault")

with st.sidebar:
    case_name = st.text_input("Case Reference / Client", "General Audit")
    uploaded_files = st.file_uploader("Upload Documents (PDF/Images)", 
                                      type=["pdf", "png", "jpg", "jpeg"], 
                                      accept_multiple_files=True)
    
    st.divider()
    if st.button("Clear Vault (DB)"):
        # Wipes historical records for a fresh audit
        supabase.table("image_inventory").delete().neq("id", 0).execute()
        st.success("Vault cleared.")

if uploaded_files:
    # Initialize categorization buckets
    diff_file = []          # Tab 1: Cross-File Matches
    same_file_diff_pg = []  # Tab 2: Internal Duplicates (Diff Pages)
    same_pg = []            # Tab 3: Recursive Matches (Same Page)
    
    # STEP 1: Batch Extraction
    # We extract all images first to ensure simultaneous matches are caught
    all_extracted_items = []
    
    for uploaded_file in uploaded_files:
        with st.status(f"Scanning {uploaded_file.name}...", expanded=False):
            if uploaded_file.type == "application/pdf":
                with pdfplumber.open(uploaded_file) as pdf:
                    for i, page in enumerate(pdf.pages):
                        for img_idx, img in enumerate(page.images):
                            try:
                                bbox = (img["x0"], img["top"], img["x1"], img["bottom"])
                                pil = page.crop(bbox).to_image(resolution=150).original
                                h = str(imagehash.phash(pil))
                                all_extracted_items.append({
                                    "name": uploaded_file.name, 
                                    "pg": i+1, 
                                    "img": pil, 
                                    "hash": h
                                })
                            except: continue
            else:
                # Handle direct image uploads
                pil = Image.open(uploaded_file)
                h = str(imagehash.phash(pil))
                all_extracted_items.append({
                    "name": uploaded_file.name, 
                    "pg": 1, 
                    "img": pil, 
                    "hash": h
                })

    # STEP 2: Priority Comparison Logic
    # This prevents the "No duplicates detected" error for same-batch uploads
    seen_in_this_session = {} # Temporary memory to track hashes in current upload

    for item in all_extracted_items:
        h = item["hash"]
        
        # A. Check Database (Historical context)
        db_res = supabase.table("image_inventory").select("*").eq("image_hash", h).execute()
        
        found_match = False

        # Check DB matches first to prioritize Tab 1 (Cross-File)
        if db_res.data:
            for m in db_res.data:
                match_entry = {"new": item, "old": m}
                if m["file_name"] != item["name"]:
                    diff_file.append(match_entry)
                elif m["page_number"] != item["pg"]:
                    same_file_diff_pg.append(match_entry)
                else:
                    same_pg.append(match_entry)
            found_match = True

        # B. Check Session Memory (Matches between files in the same upload)
        if not found_match and h in seen_in_this_session:
            prev = seen_in_this_session[h]
            match_entry = {"new": item, "old": {"file_name": prev["name"], "page_number": prev["pg"]}}
            
            # Explicitly force cross-file name check
            if prev["name"] != item["name"]:
                diff_file.append(match_entry)
            elif prev["pg"] != item["pg"]:
                same_file_diff_pg.append(match_entry)
            else:
                same_pg.append(match_entry)
            found_match = True

        # C. Save Unique Findings
        if not found_match:
            seen_in_this_session[h] = item
            supabase.table("image_inventory").insert({
                "case_name": case_name,
                "file_name": item["name"],
                "page_number": item["pg"],
                "image_hash": h
            }).execute()

    # --- 4. CATEGORIZED RESULTS DISPLAY ---
    t1, t2, t3 = st.tabs(["📁 Cross-File Matches", "📄 Internal (Diff Pages)", "📍 Same Page"])
    
    def render_tab(matches, tab_obj):
        with tab_obj:
            if not matches:
                st.info("No duplicates detected in this category.")
            else:
                for m in matches:
                    with st.expander(f"⚠️ MATCH FOUND: {m['old']['file_name']}", expanded=True):
                        c1, c2 = st.columns(2)
                        # Current Upload
                        c1.image(m['new']['img'], caption=f"Current: {m['new']['name']} (Pg {m['new']['pg']})")
                        # Matched Artifact
                        c2.image(m['new']['img'], caption=f"Matched: {m['old']['file_name']} (Pg {m['old'].get('page_number', '?')})")

    render_tab(diff_file, t1)
    render_tab(same_file_diff_pg, t2)
    render_tab(same_pg, t3)
