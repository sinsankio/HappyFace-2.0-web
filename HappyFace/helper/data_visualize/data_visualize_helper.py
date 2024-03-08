import io

import cv2
import matplotlib.pyplot as plt
import numpy as np

from helper.data_visualize.data_visualize_config_helper import DataVisualizeConfigHelper


class DataVisualizeHelper:
    @staticmethod
    def plt_to_opencv_img(plot) -> np.ndarray:
        buffer = io.BytesIO()

        plot.savefig(buffer, format="jpg", bbox_inches='tight', pad_inches=0.01)
        buffer.seek(0)

        plt_image = np.asarray(bytearray(buffer.read()), dtype=np.uint8)
        plt_opencv_image = cv2.imdecode(plt_image, cv2.IMREAD_COLOR)
        plt_opencv_image = cv2.resize(plt_opencv_image, DataVisualizeConfigHelper.IMAGE_RESOLUTION)

        return plt_opencv_image

    @staticmethod
    def plot_emotion_engagement_bar(emotion_engagement: dict) -> np.ndarray:
        figure, axis = plt.subplots()

        axis.bar(
            tuple(emotion_engagement.keys()),
            tuple(emotion_engagement.values()),
            color=DataVisualizeConfigHelper.BAR_COLOR
        )
        plt.title(DataVisualizeConfigHelper.BAR_CHART_TITLE)
        plt.xlabel(DataVisualizeConfigHelper.BAR_CHART_X_AXIS_NAME)
        plt.ylabel(DataVisualizeConfigHelper.BAR_CHART_Y_AXIS_NAME)

        return DataVisualizeHelper.plt_to_opencv_img(plt)

    @staticmethod
    def plot_emotion_engagement_pie(emotion_engagement: dict) -> np.ndarray:
        emotion_category_count = {"positive": 0, "negative": 0}

        for emotion, value in emotion_engagement.items():
            if emotion in DataVisualizeConfigHelper.EMOTIONS_BASED_ON_POSITIVITY["positive"]:
                emotion_category_count["positive"] += value
            else:
                emotion_category_count["negative"] += emotion_engagement[emotion]

        values = [emotion_category_count["positive"], emotion_category_count["negative"]]

        if values[0] > 0 or values[1] > 0:
            figure, axis = plt.subplots()

            labels = ["positive", "negative"]
            axis.pie(
                values,
                colors=[
                    DataVisualizeConfigHelper.PIE_CHART_POS_SEGMENT_COLOR,
                    DataVisualizeConfigHelper.PIE_CHART_NEG_SEGMENT_COLOR
                ],
                labels=labels,
                autopct='%1.1f%%',
                startangle=90,
                textprops={'fontsize': DataVisualizeConfigHelper.PIE_CHART_FONT_SIZE}
            )

            axis.axis("equal")
            plt.tight_layout()
            plt.title(DataVisualizeConfigHelper.PIE_CHART_TITLE)

            return DataVisualizeHelper.plt_to_opencv_img(plt)
