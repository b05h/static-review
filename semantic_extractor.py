import os
import tree_sitter_java as tsjava
from tree_sitter import Language, Parser, Query, QueryCursor

# --- 0.25.2 API UPDATE ---
JAVA_LANGUAGE = Language(tsjava.language())
parser = Parser(JAVA_LANGUAGE)

def extract_text(node, source_bytes):
    """Utility to safely extract the raw text from an AST node."""
    if not node:
        return ""
    return source_bytes[node.start_byte:node.end_byte].decode('utf-8')

def build_logic_skeletons(file_path):
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return []

    with open(file_path, "rb") as f:
        source_bytes = f.read()

    tree = parser.parse(source_bytes)
    root_node = tree.root_node
    method_query = Query(JAVA_LANGUAGE, "(method_declaration) @method")

    method_nodes = []
    for match in QueryCursor(method_query).matches(root_node):
        pattern_idx, captures = match
        if "method" in captures:
            nodes = captures["method"]
            if isinstance(nodes, list):
                method_nodes.extend(nodes)
            else:
                method_nodes.append(nodes)

    skeletons = []

    # ==========================================
    # PASS 1: EXPLICIT WEB ENDPOINTS
    # ==========================================
    for method in method_nodes:
        method_name = extract_text(method.child_by_field_name("name"), source_bytes)
        parameters = extract_text(method.child_by_field_name("parameters"), source_bytes)

        modifiers = method.child_by_field_name("modifiers")
        is_endpoint = False
        route_annotation = "None"
        security_annotations = []

        if modifiers:
            for child in modifiers.children:
                if "annotation" in child.type:
                    ann_text = extract_text(child, source_bytes)
                    if any(route in ann_text for route in ["Mapping", "Path", "GET", "POST", "PUT", "DELETE"]):
                        is_endpoint = True
                        route_annotation = ann_text
                    elif any(sec in ann_text for sec in ["Authorize", "RolesAllowed", "PermitAll", "DenyAll", "Secured"]):
                        security_annotations.append(ann_text)

        if method_name in ["doGet", "doPost", "doPut", "doDelete", "service"]:
            if "HttpServletRequest" in parameters:
                is_endpoint = True
                route_annotation = f"Servlet Method ({method_name})"

        if not is_endpoint:
            continue

        body = method.child_by_field_name("body")
        key_actions = []

        if body:
            action_query = Query(JAVA_LANGUAGE, "(method_invocation) @action")
            for match in QueryCursor(action_query).matches(body):
                pattern_idx, act_captures = match
                if "action" in act_captures:
                    nodes = act_captures["action"]
                    actions = nodes if isinstance(nodes, list) else [nodes]
                    for action in actions:
                        action_text = extract_text(action, source_bytes)
                        if not any(noise in action_text for noise in ["log.", "logger.", "System.out", "assert", "printStackTrace"]):
                            key_actions.append(action_text)

        sec_text = ", ".join(security_annotations) if security_annotations else "None detected on method."
        action_text = "\n  - ".join(key_actions) if key_actions else "No significant executions found."

        skeleton = (
            f"[ENDPOINT SKELETON]\n"
            f"- Route: {route_annotation}\n"
            f"- Method Name: {method_name}\n"
            f"- Input Parameters: {parameters}\n"
            f"- Security Annotations: {sec_text}\n"
            f"- Key Actions:\n  - {action_text}\n"
        )
        skeletons.append(skeleton)

    # ==========================================
    # PASS 2: FALLBACK MODE (Generic Logic Audit)
    # ==========================================
    if not skeletons and len(method_nodes) > 0:
        for method in method_nodes:
            method_name = extract_text(method.child_by_field_name("name"), source_bytes)
            parameters = extract_text(method.child_by_field_name("parameters"), source_bytes)
            body = method.child_by_field_name("body")

            key_actions = []
            if body:
                action_query = Query(JAVA_LANGUAGE, "(method_invocation) @action")
                for match in QueryCursor(action_query).matches(body):
                    pattern_idx, act_captures = match
                    if "action" in act_captures:
                        nodes = act_captures["action"]
                        actions = nodes if isinstance(nodes, list) else [nodes]
                        for action in actions:
                            action_text = extract_text(action, source_bytes)
                            if not any(noise in action_text for noise in ["log.", "logger.", "System.out", "assert", "printStackTrace"]):
                                key_actions.append(action_text)

            sec_text = "Fallback: General Method."
            action_text = "\n  - ".join(key_actions) if key_actions else "No significant executions found."

            skeleton = (
                f"[ENDPOINT SKELETON]\n"
                f"- Route: Public Method\n"
                f"- Method Name: {method_name}\n"
                f"- Input Parameters: {parameters}\n"
                f"- Security Annotations: {sec_text}\n"
                f"- Key Actions:\n  - {action_text}\n"
            )
            skeletons.append(skeleton)

    return skeletons

if __name__ == "__main__":
    target = "samples/command_injection.java"
    print(f"Extracting Logic Skeletons from {target}...\n")
    results = build_logic_skeletons(target)
    if not results:
        print("No methods found in file.")
    else:
        for res in results:
            print(res)
            print("==================================================")