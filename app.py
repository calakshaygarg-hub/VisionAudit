import streamlit as st
import pdfplumber
import imagehash
from PIL import Image, ImageOps
from supabase import create_client, Client

# --- 1. CORE SETUP & AUTH ---
st.set_page_config(page_title="VisionAudit: Forensic Vault", layout="wide")

if "auth" not in st.session_state: st.session_state.auth = False

def init_connection():
    try:
        return create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])
    except Exception as e:
        st.error(f"Database connection failed: {e}")
        return None

supabase = init_connection()

# --- 2. SIDEBAR (RESTORED SLIDER) ---
with st.sidebar:
    st.title("🛡️ Audit Controls")
    case_ref = st.text_input("Case Reference", "VSPL_Forensic_2026")
    
    # RESTORED: Sensitivity Slider
    threshold = st.slider("Similarity Sensitivity", 0, 16, 6, 
                          help="Lower = Stricter (Exact) | Higher = Looser (Catches compressed duplicates)")
    
    uploaded_files = st.file_uploader("Upload Artifacts", type=["pdf", "png", "jpg", "jpeg"], accept_multiple_files=True)
    
    if st.button("🚨 WIPE VAULT"):
        if supabase:
            supabase.table("image_inventory").delete().neq("id", 0).execute()
            st.success("Vault Cleared.")

# --- 3. THE OPTIMIZED ENGINE ---
if uploaded_files and supabase:
    diff_file, same_file_diff_pg, same_pg = [], [], []
    
    # Batch Status Container to prevent UI freezing
    with st.status("Performing Forensic Scan...", expanded=True) as status:
        st.write("🛰️ Synchronizing with Global Vault...")
        db_res = supabase.table("image_inventory").select("*").execute()
        vault_records = db_res.data if db_res.data else []

        current_batch_items = []
        for uploaded_file in uploaded_files:
            st.write(f"📂 Extracting: {uploaded_file.name}")
            try:
                if uploaded_file.type == "application/pdf":
                    with pdfplumber.open(uploaded_file) as pdf:
                        for i, page in enumerate(pdf.pages):
                            for img in page.images:
                                bbox = (img["x0"], img["top"], img["x1"], img["bottom"])
                                pil = page.crop(bbox).to_image(resolution=150).original
                                normalized = ImageOps.grayscale(pil)
                                h = imagehash.phash(normalized)
                                current_batch_items.append({"name": uploaded_file.name, "pg": i+1, "img": pil, "hash": h})
                else:
                    pil = Image.open(uploaded_file)
                    normalized = ImageOps.grayscale(pil)
                    h = imagehash.phash(normalized)
                    current_batch_items.append({"name": uploaded_file.name, "pg": 1, "img": pil, "hash": h})
            except Exception as e:
                st.warning(f"Could not process {uploaded_file.name}: {e}")

        st.write("🔍 Analyzing Similarity Matrix...")
        session_manifest = [] 
        for item in current_batch_items:
            h_current = item["hash"]
            match_found = False
            
            # Efficiently compare against Vault + Session
            all_potential_matches = vault_records + session_manifest
            for record in all_potential_matches:
                h_ref = imagehash.hex_to_hash(record["image_hash"]) if isinstance(record["image_hash"], str) else record["hash"]
                
                distance = h_current - h_ref
                if distance <= threshold:
                    match_found = True
                    entry = {"new": item, "old": record, "dist": distance}
                    if record["file_name"] != item["name"]:
                        diff_file.append(entry)
                    elif record["page_number"] != item["pg"]:
                        same_file_diff_pg.append(entry)
                    else:
                        same_pg.append(entry)
                    break 

            if not match_found:
                record_to_save = {
                    "case_name": case_ref, "file_name": item["name"],
                    "page_number": item["pg"], "image_hash": str(h_current),
                    "hash": h_current 
                }
                session_manifest.append(record_to_save)
                supabase.table("image_inventory").insert({
                    "case_name": case_ref, "file_name": item["name"],
                    "page_number": item["pg"], "image_hash": str(h_current)
                }).execute()
        
        status.update(label="✅ Scan Complete!", state="complete", expanded=False)

    # --- 4. DISPLAY RESULTS ---
    t1, t2, t3 = st.tabs(["📁 Cross-File Matches", "📄 Internal (Diff Pages)", "📍 Same Page"])
    # [Rendering logic remains same as previous version]
