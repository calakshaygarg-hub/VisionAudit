import streamlit as st
import pdfplumber
import imagehash
from PIL import Image
from supabase import create_client, Client

# --- 1. CONNECTION ---
st.set_page_config(page_title="VisionAudit Cloud", layout="wide")
supabase: Client = create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])

# --- 2. AUTH ---
if "auth" not in st.session_state: st.session_state.auth = False
if not st.session_state.auth:
    pw = st.text_input("Access Key", type="password")
    if st.button("Login"):
        if pw == "Audit2026!":
            st.session_state.auth = True
            st.rerun()
    st.stop()

st.title("🔍 VisionAudit: Forensic Vault")

# --- 3. AUDIT ENGINE ---
with st.sidebar:
    case_ref = st.text_input("Case Reference", "General Audit")
    uploaded_files = st.file_uploader("Upload PDFs", type=["pdf", "png", "jpg"], accept_multiple_files=True)

if uploaded_files:
    # Initialize Tab Buckets
    diff_file, same_file_diff_pg, same_pg = [], [], []

    for uploaded_file in uploaded_files:
        try:
            with st.spinner(f"Analyzing {uploaded_file.name}..."):
                # Extract Images
                imgs = []
                if uploaded_file.type == "application/pdf":
                    with pdfplumber.open(uploaded_file) as pdf:
                        for i, page in enumerate(pdf.pages):
                            for img in page.images:
                                crop = page.crop((img["x0"], img["top"], img["x1"], img["bottom"]))
                                pil = crop.to_image(resolution=150).original
                                imgs.append({"name": uploaded_file.name, "pg": i+1, "img": pil, "hash": str(imagehash.phash(pil))})
                else:
                    pil = Image.open(uploaded_file)
                    imgs.append({"name": uploaded_file.name, "pg": 1, "img": pil, "hash": str(imagehash.phash(pil))})

                # Sort and Save
                for item in imgs:
                    res = supabase.table("image_inventory").select("*").eq("image_hash", item["hash"]).execute()
                    
                    if res.data:
                        for m in res.data:
                            match_box = {"new": item, "old": m}
                            if m["file_name"] != item["name"]: diff_file.append(match_box)
                            elif m["page_number"] != item["pg"]: same_file_diff_pg.append(match_box)
                            else: same_pg.append(match_box)
                    else:
                        supabase.table("image_inventory").insert({
                            "case_name": case_ref, "file_name": item["name"], 
                            "page_number": item["pg"], "image_hash": item["hash"]
                        }).execute()
        except Exception as e:
            st.error(f"Error processing {uploaded_file.name}: {e}")

    # --- 4. TABS ---
    t1, t2, t3 = st.tabs(["📁 Different Files", "📄 Same File (Diff Pages)", "📍 Same Page"])
    
    def draw(data, tab):
        with tab:
            if not data: st.info("No duplicates.")
            for d in data:
                with st.expander(f"MATCH: {d['old']['file_name']}", expanded=True):
                    c1, c2 = st.columns(2)
                    c1.image(d['new']['img'], caption="Current")
                    c2.image(d['new']['img'], caption=f"Matched: Pg {d['old'].get('page_number')}")

    draw(diff_file, t1); draw(same_file_diff_pg, t2); draw(same_pg, t3)
