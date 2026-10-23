use accesskit::{ActionHandler, ActionRequest, Node, NodeId, Rect, Role, Tree, TreeId, TreeUpdate};
use accesskit_consumer::Tree as ConsumerTree;
use std::sync::Arc;
use windows::{
    Win32::UI::{Accessibility::*, WindowsAndMessaging::*},
    core::*,
};

use crate::context::{ActionHandlerWrapper, Context};

struct NoActions;

impl ActionHandler for NoActions {
    fn do_action(&mut self, _: ActionRequest) {}
}

#[test]
fn destroyed_window_geometry_returns_element_unavailable() -> Result<()> {
    let _guard = super::MUTEX.lock();
    let hwnd = unsafe {
        CreateWindowExW(
            Default::default(),
            w!("STATIC"),
            w!("AccessKit teardown regression"),
            WS_OVERLAPPED,
            10,
            20,
            100,
            100,
            None,
            None,
            None,
            None,
        )?
    };
    let cleanup = scopeguard::guard(hwnd, |hwnd| unsafe {
        let _ = DestroyWindow(hwnd);
    });
    let root_id = NodeId(0);
    let mut root = Node::new(Role::Window);
    root.set_bounds(Rect::new(0.0, 0.0, 80.0, 60.0));
    let tree = ConsumerTree::new(
        TreeUpdate {
            nodes: vec![(root_id, root)],
            tree: Some(Tree::new(root_id)),
            tree_id: TreeId::ROOT,
            focus: root_id,
        },
        true,
    );
    let root_id = tree.state().root_id();
    // Keep the context alive, as an in-flight callback can do during teardown.
    let context = Context::new(
        hwnd.into(),
        tree,
        Arc::new(ActionHandlerWrapper::new(NoActions)),
        false,
    );
    let provider: IRawElementProviderFragment = context
        .get_or_create_platform_node(root_id)
        .into_interface();
    let root_provider: IRawElementProviderFragmentRoot = provider.cast()?;
    let bounds = unsafe { provider.BoundingRectangle()? };
    assert_eq!(bounds.width, 80.0);
    assert_eq!(bounds.height, 60.0);
    assert!(
        unsafe { root_provider.ElementProviderFromPoint(bounds.left + 1.0, bounds.top + 1.0) }
            .is_ok()
    );

    unsafe { DestroyWindow(hwnd)? };
    scopeguard::ScopeGuard::into_inner(cleanup);

    let error = unsafe { provider.BoundingRectangle() }.unwrap_err();
    assert_eq!(error.code(), HRESULT(UIA_E_ELEMENTNOTAVAILABLE as i32));
    let error = unsafe { root_provider.ElementProviderFromPoint(11.0, 21.0) }.unwrap_err();
    assert_eq!(error.code(), HRESULT(UIA_E_ELEMENTNOTAVAILABLE as i32));
    Ok(())
}
