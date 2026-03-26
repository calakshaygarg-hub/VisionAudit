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
    st.error("❌ Supabase connection failed.")
    st.stop()

# --- 2. SIDEBAR CONTROLS ---
with st.sidebar:
    st.title("Settings")
    case_ref = st.text_input("Case Reference", "VSPL_Forensic_2026")
    
    # RESTORED: Similarity Slider
    # A lower distance (e.g., 2) is stricter; a higher distance (e.g., 12) is looser.
    threshold = st.slider("Similarity Sensitivity (Hamming Distance)", 0, 16, 6, 
                          help="Lower = Exact Matches Only | Higher = Catch compressed/resized duplicates")
    
    uploaded_files = st.file_uploader("Upload Audit Artifacts", type=["pdf", "png", "jpg", "jpeg"], accept_multiple_files=True)
    
    if st.button("🚨 WIPE VAULT (DB)"):
        supabase.table("image_inventory").delete().neq("id", 0).execute()
        st.success("Vault Cleared.")

# --- 3. COMPARISON LOGIC ---
if uploaded_files:
    diff_file, same_file_diff_pg, same_pg = [], [], []
    
    with st.spinner("Syncing Vault..."):
        db_res = supabase.table("image_inventory").select("*").execute()
        vault_records = db_res.data if db_res.data else []

    current_batch_items = []
    for uploaded_file in uploaded_files:
        # ... [Image Extraction Logic remains same as previous version] ...
        # (Grayscale normalization + pHash generation)
        pass 

    session_manifest = [] 
    for item in current_batch_items:
        h_current = item["hash"]
        match_metadata = None
        all_potential_matches = vault_records + session_manifest
        
        for record in all_potential_matches:
            h_ref = imagehash.hex_to_hash(record["image_hash"]) if isinstance(record["image_hash"], str) else record["hash"]
            
            # LINKED TO SLIDER:
            distance = h_current - h_ref
            if distance <= threshold: # Uses the slider value
                match_metadata = record
                entry = {"new": item, "old": record, "dist": distance}
                if record["file_name"] != item["name"]:
                    diff_file.append(entry)
                # ... [Rest of categorization logic] ...
                break
