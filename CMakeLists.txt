set(BLASTER_LIB ${LFL_APP_LIB} app_null_framework app_null_graphics
    app_null_audio app_null_camera app_null_matrix app_null_fft app_stdregex_regex
    app_simple_resampler app_simple_loader ${LFL_APP_CONVERT} app_openssl_crypto app_null_dh
    app_null_png app_null_jpeg app_null_gif app_null_ogg app_null_css app_null_ttf
    app_null_ssl app_null_js app_null_tu ${LFL_APP_OS})

lfl_project(blaster)
lfl_add_package(blaster EXECUTABLE SOURCES blaster.cpp LINK_LIBRARIES ${BLASTER_LIB})

lfl_project(receiver)
lfl_add_package(receiver EXECUTABLE SOURCES receiver.cpp LINK_LIBRARIES ${BLASTER_LIB})

lfl_project(resolver)
lfl_add_package(resolver EXECUTABLE SOURCES resolver.cpp LINK_LIBRARIES ${BLASTER_LIB})

lfl_project(tester)
lfl_add_package(tester EXECUTABLE SOURCES tester.cpp LINK_LIBRARIES ${BLASTER_LIB})
