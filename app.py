import streamlit as st
import pdfplumber
import imagehash
from PIL import Image
from supabase import create_client, Client

# --- 1. CORE SETUP ---
st.set_page_config(page_title="VisionAudit", layout="wide")

try:
    supabase: Client = create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])
except Exception as e:
    st.error("Check your Streamlit Secrets! The connection is failing.")
    st.stop()

# --- 2. AUTHENTICATION ---
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    pw = st.text_input("Access Key", type="password")
    if st.button("Login"):
        if pw == "Audit2026!":
            st.session_state["authenticated"] = True
            st.rerun()
    st.stop()

# --- 3. AUDIT INTERFACE ---
st.title("🔍 VisionAudit: Forensic Vault")

with st.sidebar:
    case_name = st.text_input("Case Reference", "General Audit")
    uploaded_files = st.file_uploader("Upload Documents", type=["pdf", "png", "jpg"], accept_multiple_files=True)
    if st.button("Clear Vault (DB)"):
        supabase.table("image_inventory").delete().neq("id", 0).execute()
        st.success("Vault wiped.")

if uploaded_files:
    # Match Buckets
    diff_file, same_file_diff_pg, same_pg = [], [], []
    
    # NEW: Memory to catch matches within the SAME upload batch
    session_hashes = {} 

    for uploaded_file in uploaded_files:
        try:
            with st.spinner(f"Analyzing {uploaded_file.name}..."):
                current_batch = []
                
                # --- EXTRACTION ---
                if uploaded_file.type == "application/pdf":
                    with pdfplumber.open(uploaded_file) as pdf:
                        for i, page in enumerate(pdf.pages):
                            for img in page.images:
                                try:
                                    bbox = (img["x0"], img["top"], img["x1"], img["bottom"])
                                    pil = page.crop(bbox).to_image(resolution=150).original
                                    h = str(imagehash.phash(pil))
                                    current_batch.append({"name": uploaded_file.name, "pg": i+1, "img": pil, "hash": h})
                                except: continue
                else:
                    pil = Image.open(uploaded_file)
                    h = str(imagehash.phash(pil))
                    current_batch.append({"name": uploaded_file.name, "pg": 1, "img": pil, "hash": h})

                # --- COMPARISON LOGIC ---
                for item in current_batch:
                    # A. Check against the DATABASE (Historical matches)
                    res = supabase.table("image_inventory").select("*").eq("image_hash", item["hash"]).execute()
                    
                    # B. Check against the CURRENT SESSION (Matches in the same upload)
                    if item["hash"] in session_hashes:
                        prev = session_hashes[item["hash"]]
                        # If the hash exists in session, it's a match!
                        match_entry = {"new": item, "old": {"file_name": prev["name"], "page_number": prev["pg"]}}
                        diff_file.append(match_entry)
                        
                    elif res.data:
                        # Found in the historical vault
                        for m in res.data:
                            match_entry = {"new": item, "old": m}
                            if m["file_name"] != item["name"]:
                                diff_file.append(match_entry)
                            elif m["page_number"] != item["pg"]:
                                same_file_diff_pg.append(match_entry)
                            else:
                                same_pg.append(match_entry)
                    else:
                        # COMPLETELY NEW: Save to DB and Session Memory
                        session_hashes[item["hash"]] = item
                        supabase.table("image_inventory").insert({
                            "case_name": case_name, 
                            "file_name": item["name"],
                            "page_number": item["pg"], 
                            "image_hash": item["hash"]
                        }).execute()

        except Exception as e:
            st.error(f"Error in {uploaded_file.name}: {e}")

    # --- 4. DISPLAY TABS ---
    t1, t2, t3 = st.tabs(["📁 Cross-File Matches", "📄 Internal (Diff Pages)", "📍 Same Page"])
    
    def render(matches, tab_obj):
        with tab_obj:
            if not matches:
                st.info("No duplicates detected.")
            for m in matches:
                with st.expander(f"MATCH: {m['old']['file_name']}", expanded=True):
                    c1, c2 = st.columns(2)
                    c1.image(m['new']['img'], caption=f"Current: {m['new']['name']} (Pg {m['new']['pg']})")
                    # Visual check: use the new image to show they are identical
                    c2.image(m['new']['img'], caption=f"Vault: {m['old']['file_name']} (Pg {m['old'].get('page_number', '?')})")

    render(diff_file, t1)
    render(same_file_diff_pg, t2)
    render(same_pg, t3)
