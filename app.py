import streamlit as st
import pdfplumber
import imagehash
from PIL import Image, ImageOps
from supabase import create_client, Client
import io

# --- 1. CORE SETUP & PERSISTENCE ---
st.set_page_config(page_title="VisionAudit: Forensic Vault", layout="wide")

# Initialize Session State to prevent "Blank Screen" on rerun
if "processed_items" not in st.session_state:
    st.session_state.processed_items = []
if "vault_data" not in st.session_state:
    st.session_state.vault_data = []

def init_connection():
    try:
        return create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])
    except Exception as e:
        st.error(f"Supabase Connection Error: {e}")
        return None

supabase = init_connection()

# --- 2. SIDEBAR CONTROLS ---
with st.sidebar:
    st.title("🛡️ Audit Controls")
    case_ref = st.text_input("Case Reference", "VSPL_Forensic_2026")
    
    # Restored Slider: Threshold for Hamming Distance
    threshold = st.slider("Similarity Sensitivity", 0, 20, 6, 
                          help="0 = Binary Identical | 6 = Industry Standard | 15+ = Very Loose")
    
    uploaded_files = st.file_uploader("Upload Artifacts", type=["pdf", "png", "jpg", "jpeg"], accept_multiple_files=True)
    
    if st.button("🚨 WIPE VAULT"):
        if supabase:
            supabase.table("image_inventory").delete().neq("id", 0).execute()
            st.session_state.vault_data = []
            st.success("Vault Cleared.")
            st.rerun()

# --- 3. EXTRACTION ENGINE (Runs only on new upload) ---
if uploaded_files:
    # Check if we need to process new files
    if not st.session_state.processed_items:
        with st.status("🚀 Forensic Extraction in Progress...", expanded=True) as status:
            # Sync with Database Vault
            st.write("🛰️ Fetching Historical Vault...")
            db_res = supabase.table("image_inventory").select("*").execute()
            st.session_state.vault_data = db_res.data if db_res.data else []

            temp_items = []
            for uploaded_file in uploaded_files:
                st.write(f"📂 Processing: {uploaded_file.name}")
                try:
                    if uploaded_file.type == "application/pdf":
                        with pdfplumber.open(uploaded_file) as pdf:
                            for i, page in enumerate(pdf.pages):
                                for img in page.images:
                                    bbox = (img["x0"], img["top"], img["x1"], img["bottom"])
                                    pil = page.crop(bbox).to_image(resolution=150).original
                                    # Forensic Normalization: Grayscale reduces noise
                                    normalized = ImageOps.grayscale(pil)
                                    h = imagehash.phash(normalized)
                                    temp_items.append({
                                        "name": uploaded_file.name, 
                                        "pg": i+1, "img": pil, "hash": h
                                    })
                    else:
                        pil = Image.open(uploaded_file)
                        normalized = ImageOps.grayscale(pil)
                        h = imagehash.phash(normalized)
                        temp_items.append({
                            "name": uploaded_file.name, 
                            "pg": 1, "img": pil, "hash": h
                        })
                except Exception as e:
                    st.error(f"Error extracting {uploaded_file.name}: {e}")

            st.session_state.processed_items = temp_items
            status.update(label="✅ Extraction Complete", state="complete", expanded=False)

    # --- 4. LIVE COMPARISON LOGIC (Linked to Slider) ---
    diff_file, same_file_diff_pg, same_pg = [], [], []
    
    # Compare current session items against each other and the vault
    seen_in_this_run = []
    
    for item in st.session_state.processed_items:
        h_current = item["hash"]
        match_found = False
        
        # Combine Vault and items already processed in this loop
        reference_pool = st.session_state.vault_data + seen_in_this_run
        
        for record in reference_pool:
            # Convert string hash from DB back to object if necessary
            h_ref = imagehash.hex_to_hash(record["image_hash"]) if isinstance(record["image_hash"], str) else record["hash"]
            
            distance = h_current - h_ref
            if distance <= threshold: # Live Reactivity
                match_found = True
                similarity = int(100 * (1 - (distance / 64)))
                entry = {"new": item, "old": record, "sim": similarity}
                
                if record["file_name"] != item["name"]:
                    diff_file.append(entry)
                elif record.get("page_number", 0) != item["pg"]:
                    same_file_diff_pg.append(entry)
                else:
                    same_pg.append(entry)
                break
        
        if not match_found:
            new_record = {
                "case_name": case_ref, "file_name": item["name"],
                "page_number": item["pg"], "image_hash": str(h_current),
                "hash": h_current 
            }
            seen_in_this_run.append(new_record)
            # Silently push to DB for future sessions
            supabase.table("image_inventory").insert({
                "case_name": case_ref, "file_name": item["name"],
                "page_number": item["pg"], "image_hash": str(h_current)
            }).execute()

    # --- 5. RESULTS DISPLAY ---
    st.title("🔍 VisionAudit: Forensic Vault")
    t1, t2, t3 = st.tabs(["📁 Cross-File Matches", "📄 Internal (Diff Pages)", "📍 Same Page"])
    
    def display_results(matches, tab):
        with tab:
            if not matches:
                st.info("No duplicates detected at this sensitivity level.")
            else:
                for m in matches:
                    with st.expander(f"Match Detected: {m['sim']}% Similarity", expanded=True):
                        c1, c2 = st.columns(2)
                        c1.image(m['new']['img'], caption=f"Current: {m['new']['name']} (Pg {m['new']['pg']})")
                        # Displaying the source it matched against
                        c2.image(m['new']['img'], caption=f"Matched Source: {m['old']['file_name']}")

    display_results(diff_file, t1)
    display_results(same_file_diff_pg, t2)
    display_results(same_pg, t3)

    # Footer Audit Trail
    st.divider()
    st.caption(f"Forensic Summary: {len(st.session_state.processed_items)} images analyzed | Current Threshold: {threshold}")

else:
    # Reset state if no files are uploaded
    st.session_state.processed_items = []
    st.info("Please upload PDF or Image artifacts to begin the forensic scan.")
