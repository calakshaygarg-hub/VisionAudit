import streamlit as st
import pdfplumber
import imagehash
from PIL import Image, ImageOps
from supabase import create_client, Client

# --- 1. CORE SETUP ---
st.set_page_config(page_title="VisionAudit: Forensic Vault", layout="wide")

try:
    supabase: Client = create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])
except:
    st.error("❌ Supabase connection failed. Check your Secrets.")
    st.stop()

# --- 2. AUTHENTICATION ---
if "auth" not in st.session_state: st.session_state.auth = False
if not st.session_state.auth:
    pw = st.text_input("Enter Audit Access Key", type="password")
    if st.button("Login"):
        if pw == "Audit2026!":
            st.session_state.auth = True
            st.rerun()
    st.stop()

# --- 3. AUDIT ENGINE ---
st.title("🔍 VisionAudit: Forensic Vault")

with st.sidebar:
    case_ref = st.text_input("Case Reference", "VSPL_Forensic_2026")
    uploaded_files = st.file_uploader("Upload Audit Artifacts", type=["pdf", "png", "jpg", "jpeg"], accept_multiple_files=True)
    st.divider()
    if st.button("🚨 WIPE VAULT (DB)"):
        supabase.table("image_inventory").delete().neq("id", 0).execute()
        st.success("Vault Cleared.")

if uploaded_files:
    diff_file, same_file_diff_pg, same_pg = [], [], []
    
    # STEP 1: Sync with Global Vault (Historical Data)
    with st.spinner("Synchronizing with Forensic Vault..."):
        db_res = supabase.table("image_inventory").select("*").execute()
        vault_records = db_res.data if db_res.data else []

    # STEP 2: Extraction & Normalization
    # We grayscale and normalize to ensure compression artifacts don't break the hash
    current_batch_items = []
    for uploaded_file in uploaded_files:
        with st.status(f"Extracting {uploaded_file.name}...", expanded=False):
            if uploaded_file.type == "application/pdf":
                with pdfplumber.open(uploaded_file) as pdf:
                    for i, page in enumerate(pdf.pages):
                        for img in page.images:
                            try:
                                bbox = (img["x0"], img["top"], img["x1"], img["bottom"])
                                pil = page.crop(bbox).to_image(resolution=150).original
                                normalized = ImageOps.grayscale(pil)
                                h = imagehash.phash(normalized)
                                current_batch_items.append({"name": uploaded_file.name, "pg": i+1, "img": pil, "hash": h})
                            except: continue
            else:
                pil = Image.open(uploaded_file)
                normalized = ImageOps.grayscale(pil)
                h = imagehash.phash(normalized)
                current_batch_items.append({"name": uploaded_file.name, "pg": 1, "img": pil, "hash": h})

    # STEP 3: The Comparison Matrix
    # We track unique hashes seen IN THIS SESSION separately to handle batch-upload matches
    session_manifest = [] 

    for item in current_batch_items:
        h_current = item["hash"]
        match_metadata = None

        # Check against Historical Vault + Previous items in this batch
        # We prioritize Cross-File identification
        all_potential_matches = vault_records + session_manifest
        
        for record in all_potential_matches:
            # Convert hex string back to hash object if needed
            h_ref = imagehash.hex_to_hash(record["image_hash"]) if isinstance(record["image_hash"], str) else record["hash"]
            
            # Distance threshold: 6 allows for JPEG compression noise while staying precise
            distance = h_current - h_ref
            if distance <= 6:
                match_metadata = record
                # Categorization logic based on string comparison
                entry = {"new": item, "old": record}
                if record["file_name"] != item["name"]:
                    diff_file.append(entry)
                elif record["page_number"] != item["pg"]:
                    same_file_diff_pg.append(entry)
                else:
                    same_pg.append(entry)
                break 

        if not match_metadata:
            # Item is UNIQUE: Add to Session Manifest & Database
            record_to_save = {
                "case_name": case_ref,
                "file_name": item["name"],
                "page_number": item["pg"],
                "image_hash": str(h_current),
                "hash": h_current # Keep object for session comparison
            }
            session_manifest.append(record_to_save)
            supabase.table("image_inventory").insert({
                "case_name": case_ref, "file_name": item["name"],
                "page_number": item["pg"], "image_hash": str(h_current)
            }).execute()

    # --- 4. FORENSIC REPORT DISPLAY ---
    t1, t2, t3 = st.tabs(["📁 Cross-File Matches", "📄 Internal (Diff Pages)", "📍 Same Page"])
    
    def render_matches(match_list, tab):
        with tab:
            if not match_list:
                st.info("Clean: No similarities detected.")
            else:
                for m in match_list:
                    similarity = 100 - (m['new']['hash'] - (imagehash.hex_to_hash(m['old']['image_hash']) if isinstance(m['old']['image_hash'], str) else m['old']['hash']))
                    with st.expander(f"Similarity {similarity}%: {m['old']['file_name']}", expanded=True):
                        c1, c2 = st.columns(2)
                        c1.image(m['new']['img'], caption=f"Current: {m['new']['name']} (Pg {m['new']['pg']})", use_container_width=True)
                        # Displaying the matched pair
                        c2.image(m['new']['img'], caption=f"Matched: {m['old']['file_name']} (Pg {m['old'].get('page_number', '?')})", use_container_width=True)

    render_matches(diff_file, t1)
    render_matches(same_file_diff_pg, t2)
    render_matches(same_pg, t3)
