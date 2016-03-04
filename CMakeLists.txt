set(BLASTER_LIB ${LFL_APP_LIB} app_null_os app_null_framework app_null_graphics
    app_null_audio app_null_camera app_null_matrix app_null_fft
    app_simple_resampler app_simple_loader ${LFL_APP_CONVERT}
    app_null_png app_null_jpeg app_null_gif app_null_css app_null_ttf
    app_null_ssl app_null_js app_null_tu)

lfl_project(blaster)
lfl_add_target(blaster blaster.cpp)
target_link_libraries(blaster ${BLASTER_LIB})

lfl_project(receiver)
lfl_add_target(receiver receiver.cpp)
target_link_libraries(receiver ${BLASTER_LIB})

lfl_project(resolver)
lfl_add_target(resolver resolver.cpp)
target_link_libraries(resolver ${BLASTER_LIB})

lfl_project(tester)
lfl_add_target(tester tester.cpp)
target_link_libraries(tester ${BLASTER_LIB})
