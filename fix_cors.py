content = open('sandbox_analyzer_simple.py', 'r', encoding='utf-8').read()

# Fix 1: Add CORS middleware
old1 = 'from fastapi.responses import HTMLResponse\nimport uvicorn'
new1 = 'from fastapi.responses import HTMLResponse, JSONResponse\nfrom fastapi.middleware.cors import CORSMiddleware\nimport uvicorn'
content = content.replace(old1, new1)

# Fix 2: Add middleware after app creation
old2 = 'app = FastAPI(title="SOAR Sandbox Analysis", version="1.0.0")\nanalyzer = SandboxAnalyzer()'
new2 = '''app = FastAPI(title="SOAR Sandbox Analysis", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
analyzer = SandboxAnalyzer()'''
content = content.replace(old2, new2)

# Fix 3: Fix analyze endpoint
old3 = '        result = analyzer.analyze_file(content, file.filename)\n        return result\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=str(e))'
new3 = '        filename = file.filename or "unknown_file"\n        result = analyzer.analyze_file(content, filename)\n        return JSONResponse(content=result)\n    except Exception as e:\n        return JSONResponse(status_code=500, content={"error": str(e)})'
content = content.replace(old3, new3)

open('sandbox_analyzer_simple.py', 'w', encoding='utf-8').write(content)
print('All fixes applied!')