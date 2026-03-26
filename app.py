import streamlit as st
import pdfplumber
import imagehash
from PIL import Image
import pandas as pd
from supabase import create_client, Client

# --- 1. CONFIG & CONNECTION ---
st.set_page_config(page_title="VisionAudit Cloud", layout="wide")
supabase: Client = create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])

# --- 2. AUTHENTICATION ---
def check_password():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if not st.session_state["authenticated"]:
        st.title("🔐 VisionAudit Secure Login")
        password = st.text_input("Enter Auditor Access Key", type="password")
        if st.button("Login"):
            if password == "Audit2026!":
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("Access Denied.")
        return False
    return True

if not check_password():
    st.stop()

st.title("🔍 VisionAudit: Categorized Forensic Vault")

# --- 3. AUDIT SETTINGS ---
with st.sidebar:
    case_ref = st.text_input("Case Reference / Client", "General Audit")
    uploaded_files = st.file_uploader("Upload Invoices/PDFs", type=["pdf", "png", "jpg"], accept_multiple_files=True)
    if st.button("Wipe Cloud Vault"):
        supabase.table("image_inventory").delete().neq("id", 0).execute()
        st.rerun()

if uploaded_files:
    # Storage for sorted matches
    cat_diff_file = []
    cat_same_file_diff_page = []
    cat_same_page = []

    for uploaded_file in uploaded_files:
        current_file_images = []
        
        # Extraction Logic
        if uploaded_file.type == "application/pdf":
            with pdfplumber.open(uploaded_file) as pdf:
                for i, page in enumerate(pdf.pages):
                    for img_idx, img in enumerate(page.images):
                        try:
                            page_obj = page.crop((img["x0"], img["top"], img["x1"], img["bottom"]))
                            pil_img = page_obj.to_image(resolution=150).original
                            h_str = str(imagehash.phash(pil_img))
                            current_file_images.append({
                                "name": uploaded_file.name,
                                "page": i + 1,
                                "img": pil_img,
                                "hash": h_str
                            })
                        except: continue
        else:
            pil_img = Image.open(uploaded_file)
            h_str = str(imagehash.phash(pil_img))
            current_file_images.append({"name": uploaded_file.name, "page": 1, "img": pil_img, "hash": h_str})

        # --- 4. CATEGORIZATION & SAFETY ENGINE ---
        for item in current_file_images:
            # SEARCH FIRST: This prevents the unique constraint crash
            res = supabase.table("image_inventory").select("*").eq("image_hash", item["hash"]).execute()
            
            if res.data:
                # MATCH FOUND: Sort into tabs instead of trying to save again
                for match in res.data:
                    m_data = {"new": item, "old": match}
                    if match["file_name"] != item["name"]:
                        cat_diff_file.append(m_data)
                    elif match.get("page_number") != item["page"]:
                        cat_same_file_diff_page.append(m_data)
                    else:
                        cat_same_page.append(m_data)
            else:
                # NO MATCH: Safe to insert into database
                try:
                    supabase.table("image_inventory").insert({
                        "case_name": case_ref,
                        "file_name": item["name"],
                        "page_number": item["page"],
                        "image_hash": item["hash"]
                    }).execute()
                except Exception as e:
                    # Final safety net to catch any rare race conditions
                    st.warning(f"Skipped duplicate fingerprint for {item['name']}")

    # --- 5. THE THREE-TAB DISPLAY ---
    t1, t2, t3 = st.tabs(["📁 Different Files", "📄 Same File (Diff Pages)", "📍 Same Page"])

    def show_matches(match_list, tab):
        with tab:
            if not match_list: 
                st.info("No duplicates found in this category.")
            for m in match_list:
                with st.expander(f"MATCH: {m['old']['file_name']} (Vault) vs {m['new']['name']} (New)", expanded=True):
                    c1, c2 = st.columns(2)
                    with c1:
                        st.write("**New Artifact**")
                        st.caption(f"Page: {m['new']['page']}")
                        st.image(m['new']['img'], use_container_width=True)
                    with c2:
                        st.write("**Vault Record**")
                        st.caption(f"Original Page: {m['old'].get('page_number', 'N/A')}")
                        st.image(m['new']['img'], use_container_width=True)

    show_matches(cat_diff_file, t1)
    show_matches(cat_same_file_diff_page, t2)
    show_matches(cat_same_page, t3)
