use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use vmspect::prelude::*;

#[test]
fn test_opciones_defaults_y_helpers() {
    // a) Por defecto (sin banderas): debe analizar sistema y aplicaciones
    let opc = Opciones::default();
    assert!(!opc.noapps, "Por defecto noapps debe ser false");
    assert!(!opc.nosystem, "Por defecto nosystem debe ser false");
    assert!(
        opc.debe_analizar_apps(),
        "Por defecto debe_analizar_apps() debe retornar true"
    );
    assert!(
        opc.debe_analizar_sistema(),
        "Por defecto debe_analizar_sistema() debe retornar true"
    );

    // b) Con --noapps: extrae sistema, omite aplicaciones
    let opc_noapps = Opciones {
        noapps: true,
        ..Opciones::default()
    };
    assert!(
        !opc_noapps.debe_analizar_apps(),
        "Con noapps=true, debe_analizar_apps() debe retornar false"
    );
    assert!(
        opc_noapps.debe_analizar_sistema(),
        "Con noapps=true, debe_analizar_sistema() debe permanecer true"
    );

    // c) Con --nosystem: extrae aplicaciones, omite sistema
    let opc_nosystem = Opciones {
        nosystem: true,
        ..Opciones::default()
    };
    assert!(
        opc_nosystem.debe_analizar_apps(),
        "Con nosystem=true, debe_analizar_apps() debe permanecer true"
    );
    assert!(
        !opc_nosystem.debe_analizar_sistema(),
        "Con nosystem=true, debe_analizar_sistema() debe retornar false"
    );

    // d) Con ambas banderas (--noapps y --nosystem)
    let opc_ambas = Opciones {
        noapps: true,
        nosystem: true,
        ..Opciones::default()
    };
    assert!(!opc_ambas.debe_analizar_apps());
    assert!(!opc_ambas.debe_analizar_sistema());
}

#[test]
fn test_opciones_inspeccion_alias_y_builder() {
    let token = Arc::new(AtomicBool::new(false));
    let opc: OpcionesInspeccion = OpcionesInspeccion::default().with_cancel_token(token.clone());
    assert!(opc.cancel_token.is_some());

    let ctoken = CancellationToken::new();
    let opc2 = Opciones::default()
        .with_cancellation_token(&ctoken)
        .with_qemu_nbd(std::path::PathBuf::from("/usr/bin/qemu-nbd"))
        .with_forzar_nbd(true)
        .with_socket_unix("/var/run/qemu-test.sock")
        .with_extra_nbd_args(vec!["--cache=none".into(), "--detect-zeroes=on".into()])
        .with_connection_timeout(std::time::Duration::from_secs(5))
        .with_persistente_nbd(false);

    assert!(opc2.cancel_token.is_some());
    assert_eq!(
        opc2.qemu_nbd,
        Some(std::path::PathBuf::from("/usr/bin/qemu-nbd"))
    );
    assert!(opc2.forzar_nbd);
    assert_eq!(
        opc2.socket_unix,
        Some(std::path::PathBuf::from("/var/run/qemu-test.sock"))
    );
    assert_eq!(
        opc2.args_extra_nbd,
        vec!["--cache=none".to_string(), "--detect-zeroes=on".to_string()]
    );
    assert_eq!(
        opc2.timeout_conexion,
        Some(std::time::Duration::from_secs(5))
    );
    assert!(!opc2.persistente_nbd);
}

#[test]
fn test_qemu_not_found_cuando_se_requiere_nbd() {
    let dir = tempfile::tempdir().unwrap();
    let qcow2_path = dir.path().join("server.qcow2");
    let mut f1 = std::fs::File::create(&qcow2_path).unwrap();
    use std::io::Write;
    f1.write_all(b"QFI\xfb\x00\x00\x00\x03").unwrap();

    let opciones = Opciones {
        qemu_nbd: Some(std::path::PathBuf::from("ruta_inexistente_qemu_nbd")),
        ..Opciones::default()
    };
    let motor = MotorInspeccion::new(opciones);

    let res = motor.inspeccionar(&qcow2_path);
    assert!(res.is_err(), "Debe fallar por no encontrar qemu-nbd");
    match res {
        Err(VmSpectError::QemuNotFound(msg)) => {
            assert!(
                msg.contains("No se encontró el ejecutable qemu-nbd en el sistema"),
                "Mensaje inesperado: {}",
                msg
            );
        }
        other => panic!("Esperado VmSpectError::QemuNotFound, recibido: {:?}", other),
    }
}

#[test]
fn test_procesador_concurrente_preservacion_parcial_en_cancelacion() {
    use std::thread::sleep;
    use std::time::Duration;

    let items: Vec<u32> = (1..=30).collect();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clon = cancel.clone();

    let handle = std::thread::spawn(move || {
        ProcesadorConcurrente::procesar_en_paralelo(items, Some(cancel_clon), None, 4, |item| {
            if item >= 3 {
                sleep(Duration::from_millis(40));
            }
            Ok(item * 10)
        })
    });

    sleep(Duration::from_millis(15));
    cancel.store(true, std::sync::atomic::Ordering::Release);

    let res = handle.join().expect("hilo finalizado");
    let resultados = res.expect("debe preservar resultados parciales");
    assert!(
        !resultados.is_empty(),
        "Debe contener los resultados finalizados antes de la cancelación"
    );
    assert!(
        resultados.len() < 30,
        "No deben haberse procesado todos los items"
    );
    for r in &resultados {
        assert_eq!(r % 10, 0);
    }
}

#[test]
fn test_extraccion_agnostica_sin_reglas_ni_filtros() {
    // d) Extracción agnóstica: verifica que las aplicaciones no sean filtradas por listas de ruido
    // ni categorizaciones propietarias.
    let paquetes_muestra = [
        Programa {
            nombre: "libc6".to_string(),
            version: Some("2.35-0ubuntu3".to_string()),
            editor: Some("libs".to_string()),
        },
        Programa {
            nombre: "python3-minimal".to_string(),
            version: Some("3.10.6-1".to_string()),
            editor: Some("python".to_string()),
        },
        Programa {
            nombre: "libssl3".to_string(),
            version: Some("3.0.2-0ubuntu1".to_string()),
            editor: Some("libs".to_string()),
        },
        Programa {
            nombre: "linux-image-5.15.0-generic".to_string(),
            version: Some("5.15.0-88.98".to_string()),
            editor: Some("kernel".to_string()),
        },
        Programa {
            nombre: "Siemens TIA Portal V18".to_string(),
            version: Some("18.0".to_string()),
            editor: Some("Siemens AG".to_string()),
        },
        Programa {
            nombre: "Microsoft Visual C++ 2015-2022 Redistributable (x64)".to_string(),
            version: Some("14.36.32532".to_string()),
            editor: Some("Microsoft Corporation".to_string()),
        },
    ];

    // Todos los paquetes deben conservarse íntegramente
    assert_eq!(paquetes_muestra.len(), 6);
    assert!(paquetes_muestra.iter().any(|p| p.nombre.starts_with("lib")));
    assert!(paquetes_muestra
        .iter()
        .any(|p| p.nombre.starts_with("python3")));
    assert!(paquetes_muestra
        .iter()
        .any(|p| p.nombre.contains("Redistributable")));
    assert!(paquetes_muestra
        .iter()
        .any(|p| p.nombre.contains("Siemens")));
}

#[test]
fn test_motor_con_rutas_inexistentes() {
    let ruta_invalida = std::path::Path::new("ruta_inexistente_12345.vmdk");
    let opciones = Opciones::default();
    let motor = MotorInspeccion::new(opciones);

    let res = motor.inspeccionar(ruta_invalida);
    assert!(res.is_err());
    match res {
        Err(VmSpectError::ImageNotFound(p)) => {
            assert!(p.contains("ruta_inexistente_12345.vmdk"));
        }
        other => panic!("Esperado ImageNotFound, recibido: {:?}", other),
    }
}

#[test]
fn test_api_descubrimiento_bilingue_e_integridad() {
    let dir = tempfile::tempdir().unwrap();

    // Crear imágenes de prueba
    let qcow2_path = dir.path().join("server.qcow2");
    let mut f1 = std::fs::File::create(&qcow2_path).unwrap();
    use std::io::Write;
    f1.write_all(b"QFI\xfb\x00\x00\x00\x03").unwrap();

    let raw_path = dir.path().join("backup.raw");
    let mut f2 = std::fs::File::create(&raw_path).unwrap();
    let mut raw_data = vec![0u8; 1024];
    raw_data[510] = 0x55;
    raw_data[511] = 0xAA;
    f2.write_all(&raw_data).unwrap();

    let extent_flat = dir.path().join("server-flat.vmdk");
    std::fs::File::create(&extent_flat)
        .unwrap()
        .write_all(b"extent")
        .unwrap();

    // 1. es_imagen_vm / is_vm_image
    assert!(es_imagen_vm(&qcow2_path));
    assert!(is_vm_image(&qcow2_path));
    assert!(es_imagen_vm(&raw_path));
    assert!(is_vm_image(&raw_path));
    assert!(!es_imagen_vm(&extent_flat));
    assert!(!is_vm_image(&extent_flat));

    // 2. listar_vms / list_vms
    let lista_es = listar_vms(dir.path(), false).unwrap();
    let lista_en = list_vms(dir.path(), false).unwrap();
    assert_eq!(lista_es, lista_en);
    assert_eq!(lista_es.len(), 2);
    assert!(lista_es.contains(&qcow2_path));
    assert!(lista_es.contains(&raw_path));
    assert!(!lista_es.contains(&extent_flat));

    // 3. contar_vms / count_vms
    assert_eq!(contar_vms(dir.path(), false).unwrap(), 2);
    assert_eq!(count_vms(dir.path(), false).unwrap(), 2);

    // 4. hay_vms / has_vms
    assert!(hay_vms(dir.path(), false).unwrap());
    assert!(has_vms(dir.path(), false).unwrap());

    // 5. verificar_integridad_imagen / verify_image_integrity
    assert!(verificar_integridad_imagen(&qcow2_path).unwrap());
    assert!(verify_image_integrity(&qcow2_path).unwrap());
    assert!(verificar_integridad_imagen(&raw_path).unwrap());
    assert!(verify_image_integrity(&raw_path).unwrap());

    // 6. requiere_nbd / requires_nbd / requiere_qemu / requires_qemu
    assert!(requiere_nbd(&qcow2_path).unwrap());
    assert!(requires_nbd(&qcow2_path).unwrap());
    assert!(requiere_qemu(&qcow2_path).unwrap());
    assert!(requires_qemu(&qcow2_path).unwrap());

    assert!(!requiere_nbd(&raw_path).unwrap());
    assert!(!requires_nbd(&raw_path).unwrap());
    assert!(!requiere_qemu(&raw_path).unwrap());
    assert!(!requires_qemu(&raw_path).unwrap());
}
