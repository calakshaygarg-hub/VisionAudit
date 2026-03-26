import streamlit as st
import pdfplumber
import imagehash
from PIL import Image
from supabase import create_client, Client

# --- 1. CORE SETUP ---
st.set_page_config(page_title="VisionAudit", layout="wide")

try:
    supabase: Client = create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])
except:
    st.error("Connection Error")
    st.stop()

# --- 2. AUTH ---
if "auth" not in st.session_state: st.session_state.auth = False
if not st.session_state.auth:
    pw = st.text_input("Access Key", type="password")
    if st.button("Login"):
        if pw == "Audit2026!":
            st.session_state.auth = True
            st.rerun()
    st.stop()

# --- 3. AUDIT ENGINE ---
st.title("🔍 VisionAudit: Forensic Vault")

with st.sidebar:
    case_name = st.text_input("Case Reference", "General Audit")
    uploaded_files = st.file_uploader("Upload Documents", type=["pdf", "png", "jpg"], accept_multiple_files=True)
    if st.button("Clear Vault (DB)"):
        supabase.table("image_inventory").delete().neq("id", 0).execute()
        st.success("Vault wiped.")

if uploaded_files:
    diff_file, same_file_diff_pg, same_pg = [], [], []
    
    # STEP 1: Extract EVERYTHING from the entire batch first
    all_extracted_items = []
    for uploaded_file in uploaded_files:
        with st.status(f"Extracting {uploaded_file.name}...", expanded=False):
            if uploaded_file.type == "application/pdf":
                with pdfplumber.open(uploaded_file) as pdf:
                    for i, page in enumerate(pdf.pages):
                        for img in page.images:
                            try:
                                bbox = (img["x0"], img["top"], img["x1"], img["bottom"])
                                pil = page.crop(bbox).to_image(resolution=150).original
                                h = str(imagehash.phash(pil))
                                all_extracted_items.append({"name": uploaded_file.name, "pg": i+1, "img": pil, "hash": h})
                            except: continue
            else:
                pil = Image.open(uploaded_file)
                h = str(imagehash.phash(pil))
                all_extracted_items.append({"name": uploaded_file.name, "pg": 1, "img": pil, "hash": h})

    # STEP 2: Compare the batch against itself and the database
    seen_in_this_session = {} # Hash -> Item details

    for current_item in all_extracted_items:
        h = current_item["hash"]
        
        # Check Database (Historical)
        db_res = supabase.table("image_inventory").select("*").eq("image_hash", h).execute()
        
        if h in seen_in_this_session:
            # MATCH: Found within this specific upload batch
            prev = seen_in_this_session[h]
            match_entry = {"new": current_item, "old": {"file_name": prev["name"], "page_number": prev["pg"]}}
            diff_file.append(match_entry)
        
        elif db_res.data:
            # MATCH: Found in historical records
            for m in db_res.data:
                match_entry = {"new": current_item, "old": m}
                if m["file_name"] != current_item["name"]: diff_file.append(match_entry)
                elif m["page_number"] != current_item["pg"]: same_file_diff_pg.append(match_entry)
                else: same_pg.append(match_entry)
        else:
            # UNIQUE: Save it
            seen_in_this_session[h] = current_item
            supabase.table("image_inventory").insert({
                "case_name": case_name, "file_name": current_item["name"],
                "page_number": current_item["pg"], "image_hash": h
            }).execute()

    # --- 4. DISPLAY ---
    t1, t2, t3 = st.tabs(["📁 Cross-File Matches", "📄 Internal (Diff Pages)", "📍 Same Page"])
    
    def render(matches, tab_obj):
        with tab_obj:
            if not matches: st.info("No duplicates detected.")
            for m in matches:
                with st.expander(f"DUPLICATE DETECTED: {m['old']['file_name']}", expanded=True):
                    c1, c2 = st.columns(2)
                    c1.image(m['new']['img'], caption=f"Current: {m['new']['name']} (Pg {m['new']['pg']})")
                    c2.image(m['new']['img'], caption=f"Matched: {m['old']['file_name']} (Pg {m['old'].get('page_number', '?')})")

    render(diff_file, t1); render(same_file_diff_pg, t2); render(same_pg, t3)
