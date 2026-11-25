"""Generate Hackathon Pitch Deck for RepoSentinel AI (Track 3)."""
import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

def create_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    dark_bg = RGBColor(15, 23, 42)      # Slate 900
    card_bg = RGBColor(30, 41, 59)      # Slate 800
    cyan_text = RGBColor(56, 189, 248)   # Sky 400
    white_text = RGBColor(248, 250, 252) # White
    gray_text = RGBColor(148, 163, 184)  # Slate 400
    green_text = RGBColor(74, 222, 128)  # Green 400
    amber_text = RGBColor(251, 191, 36)  # Amber 400

    blank_layout = prs.slide_layouts[6]

    def add_header(slide, title, category="TRACK 3: A COPILOT ACROSS TWO SYSTEMS"):
        bg = slide.shapes.add_shape(1, 0, 0, Inches(13.333), Inches(7.5))
        bg.fill.solid()
        bg.fill.fore_color.rgb = dark_bg
        bg.line.color.rgb = dark_bg

        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.5), Inches(11.7), Inches(0.4))
        p_cat = cat_box.text_frame.paragraphs[0]
        p_cat.text = category.upper()
        p_cat.font.size = Pt(11)
        p_cat.font.bold = True
        p_cat.font.color.rgb = cyan_text

        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.8), Inches(11.7), Inches(0.8))
        p_title = title_box.text_frame.paragraphs[0]
        p_title.text = title
        p_title.font.size = Pt(26)
        p_title.font.bold = True
        p_title.font.color.rgb = white_text

    def add_card(slide, left, top, width, height, title, points, accent_color=cyan_text):
        card = slide.shapes.add_shape(1, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = card_bg
        card.line.color.rgb = RGBColor(51, 65, 85)

        tb = slide.shapes.add_textbox(left + Inches(0.3), top + Inches(0.2), width - Inches(0.6), height - Inches(0.4))
        tf = tb.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.size = Pt(17)
        p0.font.bold = True
        p0.font.color.rgb = accent_color
        p0.space_after = Pt(12)

        for pt in points:
            p = tf.add_paragraph()
            p.text = "• " + pt
            p.font.size = Pt(13)
            p.font.color.rgb = white_text
            p.space_after = Pt(8)

    # SLIDE 1: Title
    s1 = prs.slides.add_slide(blank_layout)
    bg1 = s1.shapes.add_shape(1, 0, 0, Inches(13.333), Inches(7.5))
    bg1.fill.solid()
    bg1.fill.fore_color.rgb = dark_bg
    bg1.line.color.rgb = dark_bg

    tb1 = s1.shapes.add_textbox(Inches(1.0), Inches(1.8), Inches(11.3), Inches(3.5))
    tf1 = tb1.text_frame
    tf1.word_wrap = True

    p = tf1.paragraphs[0]
    p.text = "RepoSentinel AI"
    p.font.size = Pt(44)
    p.font.bold = True
    p.font.color.rgb = cyan_text

    p = tf1.add_paragraph()
    p.text = "Synapse-Powered Cross-System Repository Security Copilot"
    p.font.size = Pt(24)
    p.font.color.rgb = white_text
    p.space_after = Pt(18)

    p = tf1.add_paragraph()
    p.text = "2nd Brain Labs × Geek Room Vibe-a-thon | Track 3: A Copilot Across Two Systems"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = amber_text
    p.space_after = Pt(8)

    p = tf1.add_paragraph()
    p.text = "Built by Aayush | Real-Time GitHub & OSV.dev Intelligence via Synapse MCP"
    p.font.size = Pt(13)
    p.font.color.rgb = gray_text

    # SLIDE 2: Problem & Solution
    s2 = prs.slides.add_slide(blank_layout)
    add_header(s2, "The Problem & The RepoSentinel Solution")
    add_card(s2, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8), 
             "The Security Gap Between Systems", [
                 "Repository code, dependency manifests, and active PRs live in GitHub.",
                 "Global vulnerability advisories and fixes live in OSV.dev.",
                 "Engineers manually toggle between GitHub and OSV to verify vulnerabilities.",
                 "Static scanners produce false positives and lack Git commit & PR context.",
                 "Remediation status (whether an open PR fixes the CVE) remains fragmented."
             ], amber_text)
    add_card(s2, Inches(6.9), Inches(1.8), Inches(5.6), Inches(4.8), 
             "The RepoSentinel AI Solution", [
                 "Connects two independent FastAPI microservices through Synapse-generated MCP servers.",
                 "Copilot Gateway orchestrates cross-system queries using Groq & Gemini.",
                 "Correlates package versions AND Git commit SHAs directly with OSV advisories.",
                 "Cross-references open PRs to confirm whether remediation is already underway.",
                 "100% genuine live upstream APIs with zero synthetic data."
             ], green_text)

    # SLIDE 3: Architecture & 2 Independent Systems
    s3 = prs.slides.add_slide(blank_layout)
    add_header(s3, "Two Independent Systems Connected via Synapse MCP")
    add_card(s3, Inches(0.8), Inches(1.8), Inches(3.6), Inches(4.8), 
             "System 1: GitHub Service", [
                 "Port 8001 (FastAPI)",
                 "Fetches repo metadata, issues, PRs, and commit history from api.github.com.",
                 "Parses uv.lock, poetry.lock, requirements.txt, and pyproject.toml.",
                 "Separates exact pinned dependencies from unresolved ranges (no guessing)."
             ], cyan_text)
    add_card(s3, Inches(4.85), Inches(1.8), Inches(3.6), Inches(4.8), 
             "System 2: OSV Service", [
                 "Port 8002 (FastAPI)",
                 "Performs batch vulnerability lookups on api.osv.dev/v1/querybatch.",
                 "Queries commit-hash vulnerabilities via api.osv.dev/v1/query.",
                 "Caches query responses in SQLite with TTL freshness.",
                 "Provides live PyPI registry extension for latest release lookups."
             ], cyan_text)
    add_card(s3, Inches(8.9), Inches(1.8), Inches(3.6), Inches(4.8), 
             "Copilot Gateway & Agent", [
                 "Port 8000 (FastAPI)",
                 "Connects to both services via stdio MCP ClientSessions.",
                 "Groq (gpt-oss-120b) handles multi-turn dynamic tool routing.",
                 "Gemini synthesizes deep security remediation summaries.",
                 "Interactive HTML5 dashboard with live execution traces."
             ], green_text)

    # SLIDE 4: Synapse MCP Integration & Dynamic Tool Registry
    s4 = prs.slides.add_slide(blank_layout)
    add_header(s4, "Genuine Synapse MCP Tool Generation & Orchestration")
    add_card(s4, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8), 
             "Synapse Local Auto Mode", [
                 "Generated via: synapse-cli build --auto --local --all-endpoints.",
                 "Disables telemetry (SYNAPSE_TELEMETRY=0) and uses Groq (gpt-oss-120b).",
                 "GitHub MCP: 6 tools (repo metadata, dependencies, issues, PRs, commits, health).",
                 "OSV MCP: 5 tools (batch queries, commit queries, advisory lookup, health, PyPI).",
                 "Stdio protocol handles asynchronous execution seamlessly."
             ], cyan_text)
    add_card(s4, Inches(6.9), Inches(1.8), Inches(5.6), Inches(4.8), 
             "Cross-System Intelligence Workflows", [
                 "Dependency Correlation: GitHub manifest -> OSV batch query -> GitHub PR matching.",
                 "Git Commit Audit: GitHub latest commit SHA -> OSV query-commit -> Security verdict.",
                 "Dynamic Schema Registry: Gateway auto-refreshes tool schemas on demand.",
                 "Remediation Match Engine: Verifies whether open PRs mention fixed version tags."
             ], green_text)

    # SLIDE 5: The Track 3 Live Discovery Feature
    s5 = prs.slides.add_slide(blank_layout)
    add_header(s5, "Track 3 Core Requirement: Live Endpoint Discovery")
    add_card(s5, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8), 
             "Live Endpoint Injection & Discovery", [
                 "Step 1: osv_service starts with only vulnerability query endpoints.",
                 "Step 2: Live endpoint GET /registry/pypi/{package}/latest-release added.",
                 "Step 3: synapse build --auto --local --discover runs in osv_service.",
                 "Step 4: Synapse discovers the new endpoint and generates the PyPI MCP tool.",
                 "Step 5: Agent hot-reloads registry without server restart and executes the tool."
             ], amber_text)
    add_card(s5, Inches(6.9), Inches(1.8), Inches(5.6), Inches(4.8), 
             "Verifiable Proof of Live Discovery", [
                 "Tool Name: fetch_pypi_latest_release_version.",
                 "Live upstream query to https://pypi.org/pypi/{pkg}/json verified.",
                 "Agent compares installed version vs OSV fixed version vs latest PyPI release.",
                 "Zero mock data, 100% verified with automated tests."
             ], green_text)

    # SLIDE 6: OSV Commit Hash Vulnerability Intelligence
    s6 = prs.slides.add_slide(blank_layout)
    add_header(s6, "OSV Commit Hash Vulnerability Intelligence")
    add_card(s6, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8), 
             "Git Commit Security Inspection", [
                 "Standard vulnerability scanners only check package names and version strings.",
                 "RepoSentinel queries OSV.dev with exact 40- or 64-char Git commit SHAs.",
                 "Validates SHA regex, prevents injection, and handles pagination tokens.",
                 "SQLite cache records source_url, response code, and fetched_at timestamp."
             ], cyan_text)
    add_card(s6, Inches(6.9), Inches(1.8), Inches(5.6), Inches(4.8), 
             "Live OSV Verified Test Case", [
                 "Target Commit: 6879efc2c1596d11a6a6ad296f80063b558d5e0f",
                 "Verified Findings: 3 known vulnerabilities identified.",
                 "Identified Advisories: CVE-2023-25193, CVE-2026-22693, OSV-2020-484.",
                 "Agent explains zero-vulnerability caveat: 0 hits does not mean vulnerability-free."
             ], green_text)

    # SLIDE 7: Verification & Engineering Quality
    s7 = prs.slides.add_slide(blank_layout)
    add_header(s7, "Engineering Excellence & Verification Metrics")
    add_card(s7, Inches(0.8), Inches(1.8), Inches(3.6), Inches(4.8), 
             "Ruff & Quality", [
                 "Zero linter errors across all codebases.",
                 "Ruff formatted (PEP 8 compliant).",
                 "Strict typing with Pydantic v2 schemas.",
                 "Pip check passes with no broken dependencies."
             ], green_text)
    add_card(s7, Inches(4.85), Inches(1.8), Inches(3.6), Inches(4.8), 
             "Automated Tests", [
                 "60 unit and integration tests passing.",
                 "Mocked offline tests for CI/CD.",
                 "Live API tests for GitHub, OSV, Groq, Gemini, and PyPI.",
                 "verify_all.ps1 one-click automated verification."
             ], cyan_text)
    add_card(s7, Inches(8.9), Inches(1.8), Inches(3.6), Inches(4.8), 
             "Security & Safety", [
                 "Strict .gitignore protects secrets (.env, caches, DBs).",
                 "Safe API key handling (no secrets logged).",
                 "Rate-limit handling with exponential backoff.",
                 "SQLite cache prevents unnecessary upstream calls."
             ], green_text)

    # SLIDE 8: Summary & Final Submission
    s8 = prs.slides.add_slide(blank_layout)
    add_header(s8, "Submission Summary & Deliverables")
    add_card(s8, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8), 
             "Track 3 Criteria Checklist", [
                 "✓ Two independent FastAPI codebases (ports 8001 & 8002).",
                 "✓ Two genuine Synapse-generated MCP servers.",
                 "✓ One AI agent dynamically orchestrating across both systems.",
                 "✓ Genuine cross-system data retrieval and reasoning.",
                 "✓ Live endpoint addition followed by synapse build --discover.",
                 "✓ Immediate agent discovery & execution of new PyPI tool."
             ], green_text)
    add_card(s8, Inches(6.9), Inches(1.8), Inches(5.6), Inches(4.8), 
             "Project Links & Repositories", [
                 "GitHub Repository: https://github.com/Aayush033/reposentinel_ai",
                 "Hackathon Track: Track 3 — A Copilot Across Two Systems",
                 "License: Open Source (MIT-style)",
                 "Documentation: Comprehensive README.md with full setup & demo scripts."
             ], cyan_text)

    out_path = os.path.join(os.getcwd(), "presentation.pptx")
    prs.save(out_path)
    print(f"Presentation saved successfully to {out_path}")

if __name__ == "__main__":
    create_deck()
