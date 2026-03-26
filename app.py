import streamlit as st
import pdfplumber
import imagehash
from PIL import Image
from supabase import create_client, Client

# --- 1. CORE SETUP ---
st.set_page_config(page_title="VisionAudit Forensic Vault", layout="wide")

try:
    supabase: Client = create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])
except:
    st.error("Connection Error: Check Streamlit Secrets.")
    st.stop()

# --- 2. AUTH ---
if "auth" not in st.session_state: st.session_state.auth = False
if not st.session_state.auth:
    pw = st.text_input("Audit Access Key", type="password")
    if st.button("Login"):
        if pw == "Audit2026!":
            st.session_state.auth = True
            st.rerun()
    st.stop()

# --- 3. AUDIT INTERFACE ---
st.title("🔍 VisionAudit: Forensic Vault")

with st.sidebar:
    case_name = st.text_input("Case Reference", "VSPL Review")
    uploaded_files = st.file_uploader("Upload Documents", type=["pdf", "png", "jpg", "jpeg"], accept_multiple_files=True)
    if st.button("Wipe Vault"):
        supabase.table("image_inventory").delete().neq("id", 0).execute()
        st.success("Vault Cleared.")

if uploaded_files:
    diff_file, same_file_diff_pg, same_pg = [], [], []
    
    # STEP 1: Fetch ALL historical hashes from Supabase to allow for "Similarity" checks
    with st.spinner("Syncing with Vault..."):
        db_records = supabase.table("image_inventory").select("*").execute().data
    
    # STEP 2: Extraction Batch
    all_extracted = []
    for uploaded_file in uploaded_files:
        with st.status(f"Scanning {uploaded_file.name}...", expanded=False):
            if uploaded_file.type == "application/pdf":
                with pdfplumber.open(uploaded_file) as pdf:
                    for i, page in enumerate(pdf.pages):
                        for img in page.images:
                            try:
                                bbox = (img["x0"], img["top"], img["x1"], img["bottom"])
                                pil = page.crop(bbox).to_image(resolution=150).original
                                h = imagehash.phash(pil) # Keep as object for math
                                all_extracted.append({"name": uploaded_file.name, "pg": i+1, "img": pil, "hash": h})
                            except: continue
            else:
                pil = Image.open(uploaded_file)
                h = imagehash.phash(pil)
                all_extracted.append({"name": uploaded_file.name, "pg": 1, "img": pil, "hash": h})

    # STEP 3: "Fuzzy" Comparison Logic (Hamming Distance)
    # This catches 1.jpeg and 2.jpeg even if they have different file sizes
    seen_so_far = [] # List of dicts: {"hash": h, "name": n, "pg": p}

    for item in all_extracted:
        h_current = item["hash"]
        match_found = False

        # Compare against Database + Current Session
        potential_matches = db_records + seen_so_far

        for record in potential_matches:
            # Convert stored string hash back to object if needed
            h_ref = imagehash.hex_to_hash(record["image_hash"]) if isinstance(record["image_hash"], str) else record["hash"]
            
            # THE KEY: If distance <= 2, they are effectively the same image
            if (h_current - h_ref) <= 2: 
                match_entry = {"new": item, "old": record}
                
                if record["file_name"] != item["name"]:
                    diff_file.append(match_entry)
                elif record["page_number"] != item["pg"]:
                    same_file_diff_pg.append(match_entry)
                else:
                    same_pg.append(match_entry)
                
                match_found = True
                break # Found the match, move to next image

        if not match_found:
            # Save Unique item
            seen_so_far.append({"hash": h_current, "image_hash": str(h_current), "file_name": item["name"], "page_number": item["pg"]})
            supabase.table("image_inventory").insert({
                "case_name": case_name, "file_name": item["name"],
                "page_number": item["pg"], "image_hash": str(h_current)
            }).execute()

    # --- 4. DISPLAY ---
    t1, t2, t3 = st.tabs(["📁 Cross-File Matches", "📄 Internal (Diff Pages)", "📍 Same Page"])
    
    def draw(matches, tab_obj):
        with tab_obj:
            if not matches: st.info("Clean: No matches found.")
            for m in matches:
                with st.expander(f"⚠️ AUDIT ALERT: {m['old']['file_name']}", expanded=True):
                    c1, c2 = st.columns(2)
                    # Fixed: using 'use_container_width' to stop warnings
                    c1.image(m['new']['img'], caption=f"Current: {m['new']['name']} (Pg {m['new']['pg']})", use_container_width=True)
                    c2.image(m['new']['img'], caption=f"Vault Match: {m['old']['file_name']} (Pg {m['old'].get('page_number', '?')})", use_container_width=True)

    draw(diff_file, t1); draw(same_file_diff_pg, t2); draw(same_pg, t3)
