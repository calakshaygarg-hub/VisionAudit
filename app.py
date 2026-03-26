import streamlit as st
import pdfplumber
import imagehash
from PIL import Image
import pandas as pd
from supabase import create_client, Client

# --- 1. CONFIG ---
st.set_page_config(page_title="VisionAudit Cloud", layout="wide")
supabase: Client = create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])

# --- 2. AUTH ---
def check_password():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if not st.session_state["authenticated"]:
        st.title("🔐 VisionAudit Secure Login")
        pw = st.text_input("Enter Auditor Access Key", type="password")
        if st.button("Login"):
            if pw == "Audit2026!":
                st.session_state["authenticated"] = True
                st.rerun()
            else: st.error("Denied")
        return False
    return True

if not check_password(): st.stop()

st.title("🔍 VisionAudit: Forensic Vault")

# --- 3. AUDIT SETTINGS ---
with st.sidebar:
    case_ref = st.text_input("Case Reference", "General Audit")
    uploaded_files = st.file_uploader("Upload PDFs", type=["pdf", "png", "jpg"], accept_multiple_files=True)
    if st.button("Wipe Vault"):
        supabase.table("image_inventory").delete().neq("id", 0).execute()
        st.rerun()

if uploaded_files:
    # Match Buckets
    cat_diff_file = []
    cat_same_file_diff_page = []
    cat_same_page = []

    for uploaded_file in uploaded_files:
        with st.status(f"Processing {uploaded_file.name}...", expanded=False):
            images_to_process = []
            
            # --- Extraction ---
            if uploaded_file.type == "application/pdf":
                with pdfplumber.open(uploaded_file) as pdf:
                    for i, page in enumerate(pdf.pages):
                        for img_idx, img in enumerate(page.images):
                            try:
                                bbox = (img["x0"], img["top"], img["x1"], img["bottom"])
                                pil_img = page.crop(bbox).to_image(resolution=150).original
                                h_str = str(imagehash.phash(pil_img))
                                images_to_process.append({
                                    "name": uploaded_file.name, "page": i + 1,
                                    "img": pil_img, "hash": h_str
                                })
                            except: continue
            else:
                pil_img = Image.open(uploaded_file)
                h_str = str(imagehash.phash(pil_img))
                images_to_process.append({"name": uploaded_file.name, "page": 1, "img": pil_img, "hash": h_str})

            # --- Database Logic ---
            for item in images_to_process:
                # 1. Search Vault
                res = supabase.table("image_inventory").select("*").eq("image_hash", item["hash"]).execute()
                
                if res.data:
                    for match in res.data:
                        m_wrap = {"new": item, "old": match}
                        if match["file_name"] != item["name"]:
                            cat_diff_file.append(m_wrap)
                        elif match.get("page_number") != item["page"]:
                            cat_same_file_diff_page.append(m_wrap)
                        else:
                            cat_same_page.append(m_wrap)
                else:
                    # 2. Save New Unique Artifact
                    supabase.table("image_inventory").insert({
                        "case_name": case_ref,
                        "file_name": item["name"],
                        "page_number": item["page"],
                        "image_hash": item["hash"]
                    }).execute()

    # --- 4. CATEGORIZED TABS ---
    t1, t2, t3 = st.tabs(["📁 Cross-File Matches", "📄 Internal (Diff Pages)", "📍 Same Page"])

    def render(matches, tab):
        with tab:
            if not matches: st.info("Clear.")
            for m in matches:
                with st.expander(f"MATCH: Found in {m['old']['file_name']}", expanded=True):
                    c1, c2 = st.columns(2)
                    c1.image(m['new']['img'], caption=f"New: {m['new']['name']} (Pg {m['new']['page']})")
                    c2.image(m['new']['img'], caption=f"Vault: {m['old']['file_name']} (Pg {m['old'].get('page_number', '?')})")

    render(cat_diff_file, t1)
    render(cat_same_file_diff_page, t2)
    render(cat_same_page, t3)
